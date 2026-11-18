# Internal atomic record backends. Protocol packages own their transitions.
namespace eval ::oauth2::store {}
oo::class create ::oauth2::store::Memory {
    variable records
    constructor {} {set records {}}
    method durable {} {return 0}
    method atomic {command} {
        set before $records
        try {{*}$command} on error {message opts} {set records $before; return -options $opts $message}
    }
    method get {kind id now} {
        if {![dict exists $records $kind $id]} {return {}}
        set record [dict get $records $kind $id]
        if {[dict get $record expires] <= $now} {return {}}
        return $record
    }
    method put {kind id data expires {group {}}} {
        if {[dict exists $records $kind $id]} {::oauth2::core::fail conflict "Record already exists"}
        dict set records $kind $id [dict create data $data expires $expires revision 0 group $group]
    }
    method replace {kind id old data} {
        if {![dict exists $records $kind $id] || [dict get $records $kind $id revision] != [dict get $old revision]} {return 0}
        dict set records $kind $id data $data
        dict set records $kind $id revision [expr {[dict get $old revision]+1}]
        return 1
    }
    method delete {kind id old} {
        if {![dict exists $records $kind $id] || [dict get $records $kind $id revision] != [dict get $old revision]} {return 0}
        dict unset records $kind $id
        return 1
    }
    method prune {now} {
        set count 0
        dict for {kind items} $records {
            dict for {id item} $items {if {[dict get $item expires] <= $now} {dict unset records $kind $id; incr count}}
        }
        return $count
    }
}
proc ::oauth2::store::memory {} {::oauth2::store::Memory new}
proc ::oauth2::store::initdb {connection} {
    package require tpersist 0.1.5
    variable root
    ::tpersist::db_apply_schema $connection [file join $root sql schema.json]
}
set ::oauth2::store::root [file dirname [file dirname [info script]]]
oo::class create ::oauth2::store::Sql {
    variable db tenant
    constructor {connection namespace} {
        package require tpersist 0.1.5
        if {[::tpersist::db_dialect $connection] ni {sqlite postgresql}} {error "OAuth storage requires SQLite or PostgreSQL"}
        if {$namespace eq {}} {error "OAuth storage requires an explicit tenant"}
        set db $connection; set tenant $namespace
    }
    method atomic {command} {::tpersist::db_transaction $db $command}
    method durable {} {return 1}
    method where {kind id {revision {}}} {
        set terms {}
        foreach {name value type} [list tenant $tenant text kind $kind text id $id text] {
            lappend terms [::tpersist::db_eq [::tpersist::db_col $name] [::tpersist::db_value $value -type $type]]
        }
        if {$revision ne {}} {lappend terms [::tpersist::db_eq [::tpersist::db_col revision] [::tpersist::db_value $revision -type bigint]]}
        ::tpersist::db_and {*}$terms
    }
    method values {fields} {
        set result {}
        dict for {name value} $fields {
            dict set result $name [::tpersist::db_value $value -type [expr {$name in {expires revision} ? "bigint" : "text"}]]
        }
        return $result
    }
    method get {kind id now} {
        set query [::tpersist::db_where [::tpersist::db_select oauth2_records] [my where $kind $id]]
        set row [lindex [dict get [::tpersist::db_execute $db $query] rows] 0]
        if {$row eq {} || [dict get $row expires] <= $now} {return {}}
        dict create data [dict get $row data] expires [dict get $row expires] revision [dict get $row revision] group [dict get $row group_id]
    }
    method put {kind id data expires {group {}}} {
        set fields [dict create tenant $tenant kind $kind id $id data $data expires $expires revision 0 group_id $group]
        ::tpersist::db_execute $db [::tpersist::db_values [::tpersist::db_insert oauth2_records] [my values $fields] -expressions]
    }
    method replace {kind id old data} {
        set update [::tpersist::db_values [::tpersist::db_update oauth2_records] [my values [dict create data $data revision [expr {[dict get $old revision]+1}]]] -expressions]
        dict get [::tpersist::db_execute $db [::tpersist::db_where $update [my where $kind $id [dict get $old revision]]]] rowcount
    }
    method delete {kind id old} {
        dict get [::tpersist::db_execute $db [::tpersist::db_where [::tpersist::db_delete oauth2_records] [my where $kind $id [dict get $old revision]]]] rowcount
    }
    method prune {now} {
        set where [::tpersist::db_and [::tpersist::db_eq [::tpersist::db_col tenant] [::tpersist::db_value $tenant -type text]] \
            [::tpersist::db_le [::tpersist::db_col expires] [::tpersist::db_value $now -type bigint]]]
        dict get [::tpersist::db_execute $db [::tpersist::db_where [::tpersist::db_delete oauth2_records] $where]] rowcount
    }
}
proc ::oauth2::store::sql {connection tenant} {::oauth2::store::Sql new $connection $tenant}

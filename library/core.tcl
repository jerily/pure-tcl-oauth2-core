# SPDX-License-Identifier: MIT
package require Tcl 9.1
package require tjson 1.0.28
package require thashlib 0.1.1
package require tink 20240704.0.3
namespace eval ::oauth2::core {}

proc ::oauth2::core::fail {code message} {
    return -code error -errorcode [list OAUTH2 $code] $message
}
proc ::oauth2::core::options {defaults args} {
    if {[llength $args] % 2} {fail invalid_request "Options must be name/value pairs"}
    foreach {key value} $args {
        if {![dict exists $defaults $key]} {fail invalid_request "Unknown option: $key"}
        dict set defaults $key $value
    }
    return $defaults
}
proc ::oauth2::core::json {text} {
    if {[catch {::tjson::json_to_typed_strict $text} result]} {fail invalid_response "Invalid JSON document"}
    if {[lindex $result 0] ne "M"} {fail invalid_response "Expected a JSON object"}
    lindex $result 1
}
proc ::oauth2::core::json_bytes {bytes} {
    if {[catch {encoding convertfrom -profile strict utf-8 $bytes} text]} {fail invalid_response "Invalid UTF-8 response"}
    json $text
}
proc ::oauth2::core::encode_json {fields} {::tjson::typed_to_json [list M $fields]}
proc ::oauth2::core::value {fields name type args} {
    if {![dict exists $fields $name]} {
        if {[llength $args]} {return [lindex $args 0]}
        fail invalid_response "Missing required field: $name"
    }
    lassign [dict get $fields $name] actual value
    if {$actual ne $type} {fail invalid_response "Invalid field type: $name"}
    return $value
}
proc ::oauth2::core::claim_string {fields name args} {
    set result [value $fields $name S {*}$args]
    if {![llength $args] && $result eq {}} {fail invalid_response "Empty required field: $name"}
    return $result
}
proc ::oauth2::core::integer {value {minimum 0} {maximum 253402300799}} {
    # JSON numbers may have an integral double representation after parsing.
    if {![string is double -strict $value] || !($value >= $minimum && $value <= $maximum) || $value != floor($value)} {
        fail invalid_request "Expected a bounded integer"
    }
    expr {wide($value)}
}
proc ::oauth2::core::b64encode {bytes} {
    string trimright [string map {+ - / _} [binary encode base64 -maxlen 0 $bytes]] =
}
proc ::oauth2::core::b64decode {text} {
    if {![regexp {^[A-Za-z0-9_-]*$} $text] || [string length $text] % 4 == 1} {fail invalid_token "Invalid base64url"}
    set padded [string map {- + _ /} $text]
    append padded [string repeat = [expr {(4 - [string length $padded] % 4) % 4}]]
    if {[catch {binary decode base64 -strict $padded} bytes] || [b64encode $bytes] ne $text} {fail invalid_token "Non-canonical base64url"}
    return $bytes
}
proc ::oauth2::core::random {{bytes 32}} {b64encode [::thashlib::random_bytes $bytes]}
proc ::oauth2::core::digest {text} {::thashlib::sha256 -hex [encoding convertto utf-8 $text]}
proc ::oauth2::core::equal {a b} {::thashlib::constant_time_equal [encoding convertto utf-8 $a] [encoding convertto utf-8 $b]}
proc ::oauth2::core::pkce_challenge {verifier} {
    if {![regexp {^[A-Za-z0-9._~-]{43,128}$} $verifier]} {fail invalid_grant "Invalid PKCE verifier"}
    b64encode [::thashlib::sha256 [encoding convertto ascii $verifier]]
}
proc ::oauth2::core::pkce {} {
    set verifier [random]
    dict create code_verifier $verifier code_challenge [pkce_challenge $verifier] code_challenge_method S256
}
proc ::oauth2::core::scopes {scope} {
    if {$scope eq {}} {return {}}
    if {![regexp {^[\x21\x23-\x5b\x5d-\x7e]+(?: [\x21\x23-\x5b\x5d-\x7e]+)*$} $scope]} {fail invalid_scope "Invalid scope"}
    lsort -unique [split $scope { }]
}
proc ::oauth2::core::scope_subset {requested allowed} {
    set allowed [scopes $allowed]
    foreach scope [scopes $requested] {if {$scope ni $allowed} {fail invalid_scope "Requested scope is not permitted"}}
    return $requested
}
proc ::oauth2::core::url {url {local 0}} {
    if {[regexp {[\x00-\x20\x7f\\]} $url] ||
        ![regexp {^(https?)://(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.-]+)(?::([0-9]+))?(/[^#]*)?$} $url -> scheme host port path]} {
        fail invalid_request "Invalid endpoint URL"
    }
    if {$port ne {} && ($port < 1 || $port > 65535)} {fail invalid_request "Invalid URL port"}
    if {$scheme ne "https" && (!$local || $host ni {localhost 127.0.0.1 {[::1]}})} {fail invalid_request "HTTPS is required"}
    return $url
}
proc ::oauth2::core::percent {text} {
    set result {}
    binary scan [encoding convertto utf-8 $text] cu* bytes
    foreach byte $bytes {
        set c [format %c $byte]
        if {[regexp {^[A-Za-z0-9._~-]$} $c]} {append result $c} else {append result %[format %02X $byte]}
    }
    return $result
}
proc ::oauth2::core::form_encode {fields} {
    set result {}
    dict for {key value} $fields {lappend result [percent $key]=[percent $value]}
    join $result &
}
proc ::oauth2::core::form_decode {body} {
    if {[string length $body] > 32768} {fail invalid_request "Request is too large"}
    set fields {}
    if {$body eq {}} {return $fields}
    foreach pair [split $body &] {
        set at [string first = $pair]
        if {$at < 0} {fail invalid_request "Malformed form"}
        set decoded {}
        foreach text [list [string range $pair 0 [expr {$at-1}]] [string range $pair [expr {$at+1}] end]] {
            set bytes {}
            for {set i 0} {$i < [string length $text]} {incr i} {
                set c [string index $text $i]
                if {$c eq "%"} {
                    set hex [string range $text [expr {$i+1}] [expr {$i+2}]]
                    if {![regexp {^[0-9A-Fa-f]{2}$} $hex]} {fail invalid_request "Malformed percent encoding"}
                    append bytes [binary decode hex $hex]; incr i 2
                } elseif {$c eq "+"} {append bytes { }} else {
                    scan $c %c n
                    if {$n > 127 || $n < 32} {fail invalid_request "Malformed form encoding"}
                    append bytes $c
                }
            }
            if {[catch {encoding convertfrom -profile strict utf-8 $bytes} text] || [string first \x00 $text] >= 0} {fail invalid_request "Invalid form text"}
            lappend decoded $text
        }
        lassign $decoded name value
        if {$name eq {} || [dict exists $fields $name]} {fail invalid_request "Duplicate or empty parameter"}
        dict set fields $name $value
    }
    return $fields
}
proc ::oauth2::core::query_url {url fields} {
    append url [expr {[string first ? $url] < 0 ? "?" : "&"}] [form_encode $fields]
}
proc ::oauth2::core::return_path {value} {
    if {[string length $value] > 4096 || [regexp {[\\\x00-\x20\x7f]} $value]} {fail invalid_request "Invalid return destination"}
    set path [lindex [split $value ?#] 0]
    set path [dict get [form_decode p=[string map {& %26 = %3D + %2B} $path]] p]
    if {![string match /* $path] || [string match //* $path] || [regexp {[%\\\x00-\x20\x7f]} $path]} {fail invalid_request "Invalid return destination"}
    return $value
}
proc ::oauth2::core::bearer {header} {
    if {![regexp -nocase {^Bearer ([A-Za-z0-9._~+/-]+=*)$} $header -> token]} {fail invalid_token "Bearer authorization is required"}
    return $token
}
proc ::oauth2::core::response {fields {status 200}} {
    dict create statusCode $status headers {Content-Type application/json Cache-Control no-store Pragma no-cache} body [encode_json $fields]
}
proc ::oauth2::core::error_response {code {status 400}} {
    response [dict create error [list S $code]] $status
}

# Decode only for preflight policy/key selection. These values remain untrusted.
proc ::oauth2::core::jwt_parts {compact algorithms} {
    if {[string length $compact] > 65536 || [llength [split $compact .]] != 3} {fail invalid_token "Invalid JWT"}
    lassign [split $compact .] header claims signature
    if {$signature eq {}} {fail invalid_token "Unsigned JWT is forbidden"}
    b64decode $signature
    set header [json_bytes [b64decode $header]]
    set claims [json_bytes [b64decode $claims]]
    set alg [claim_string $header alg]
    if {$alg eq "none" || $alg ni $algorithms} {fail invalid_token "JWT algorithm is not permitted"}
    foreach field {crit b64 jku x5u jwk} {if {[dict exists $header $field]} {fail invalid_token "Unsupported JWT header"}}
    dict create header $header claims $claims alg $alg
}
proc ::oauth2::core::jwks_key {jwks kid alg} {
    set matches {}
    foreach entry [value $jwks keys L] {
        if {[lindex $entry 0] ne "M"} {fail invalid_response "Invalid JWK"}
        set key [lindex $entry 1]
        if {$kid ne {} && [claim_string $key kid {}] ne $kid} {continue}
        if {[claim_string $key use sig] ne "sig" || [claim_string $key alg $alg] ne $alg} {continue}
        set kty [claim_string $key kty]
        if {([string match RS* $alg] || [string match PS* $alg]) && $kty ne "RSA"} {continue}
        if {[string match ES* $alg] && $kty ne "EC"} {continue}
        if {$kty ni {RSA EC}} {continue}
        foreach secret {d p q dp dq qi k} {if {[dict exists $key $secret]} {fail invalid_response "Private material in public JWKS"}}
        if {[dict exists $key key_ops]} {
            set operations {}
            foreach op [value $key key_ops L] {
                if {[lindex $op 0] ne "S"} {fail invalid_response "Invalid JWK operations"}
                lappend operations [lindex $op 1]
            }
            if {"verify" ni $operations || "sign" in $operations} {continue}
        }
        dict set key alg [list S $alg]
        lappend matches [list M $key]
    }
    if {[llength $matches] != 1} {fail unknown_key "No unique verification key"}
    if {[catch {::tink::jwt::import_jwks [encode_json [dict create keys [list L $matches]]]} handle]} {fail invalid_token "Invalid verification key"}
    return $handle
}
proc ::oauth2::core::jwt_verify {key compact args} {
    set opts [options {-algorithms {RS256} -issuer {} -audience {} -nonce {} -type {} -now {} -skew 60 -access_token {} -mac false} {*}$args]
    set parsed [jwt_parts $compact [dict get $opts -algorithms]]
    set fields [dict get $parsed claims]
    set issuer [claim_string $fields iss]
    if {$issuer ni [dict get $opts -issuer] || [dict get $opts -audience] eq {}} {fail invalid_token "Unexpected issuer or audience"}
    foreach claim {exp iat} {integer [value $fields $claim N]}
    if {[value $fields exp N] <= [value $fields iat N]} {fail invalid_token "Invalid token lifetime"}
    claim_string $fields sub
    if {[dict exists $fields nbf]} {integer [value $fields nbf N]}
    set now [dict get $opts -now]
    if {$now eq {}} {set now [clock seconds]}
    set validator [dict create issuer $issuer audience [dict get $opts -audience] now $now clock_skew [dict get $opts -skew]]
    if {[dict get $opts -type] ne {}} {dict set validator type [dict get $opts -type]}
    set verify [expr {[dict get $opts -mac] ? "::tink::jwt::mac_verify" : "::tink::jwt::verify"}]
    if {[catch {$verify $key $compact $validator}]} {fail invalid_token "JWT verification failed"}
    if {[dict get $opts -nonce] ne {} && ![equal [claim_string $fields nonce] [dict get $opts -nonce]]} {fail invalid_token "Invalid nonce"}
    if {[dict exists $fields azp] && [claim_string $fields azp] ne [dict get $opts -audience]} {fail invalid_token "Invalid authorized party"}
    if {[lindex [dict get $fields aud] 0] eq "L" && [llength [lindex [dict get $fields aud] 1]] > 1 && ![dict exists $fields azp]} {
        fail invalid_token "Multiple audiences require an authorized party"
    }
    if {[dict exists $fields at_hash] && [dict get $opts -access_token] ne {}} {
        set algorithm [string range [dict get $parsed alg] end-2 end]
        set digest [::thashlib::sha$algorithm [encoding convertto ascii [dict get $opts -access_token]]]
        set expected [b64encode [string range $digest 0 [expr {[string length $digest]/2-1}]]]
        if {![equal [claim_string $fields at_hash] $expected]} {fail invalid_token "Invalid access token binding"}
    }
    # Return the strictly parsed original payload only after Tink accepted it.
    return $fields
}
source [file join [file dirname [info script]] store.tcl]
package provide pure-tcl-oauth2-core 0.1.0

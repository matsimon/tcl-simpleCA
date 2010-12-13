# SimpleCA
#
# Simple utility to manage X.509 Certificates
# 
# Copyright 2001 Joris Ballet 
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

set g_iso3166_codes {
Afghanistan AF Albania AL Algeria DZ {American Samoa} AS Andorra AD Angola AO Anguilla AI Antarctica AQ
{Antigua and Barbuda} AG Argentina AR Armenia AM Aruba AW Australia AU Austria AT Azerbaijan AZ
Bahamas BS Bahrain BH Bangladesh BD Barbados BB Belarus BY Belgium BE Belize BZ Benin BJ Bermuda BM 
Bhutan BT Bolivia BO {Bosnia and Herzegowina} BA Botswana BW {Bouvet Island} BV Brazil BR 
{British Indian Ocean Territory} IO {Brunei Darussalam} BN Bulgaria BG {Burkina Faso} BF Burundi BI 
Cambodia KH Cameroon CM Canada CA {Cape Verde} CV {Cayman Islands} KY {Central African Republic} CF 
Chad TD Chile CL China CN {Christmas Island} CX {Cocos (Keeling) Islands} CC Colombia CO Comoros KM 
Congo CG {Congo, The Democratic Republic of the} CD {Cook Islands} CK {Costa Rica} CR {Cote D'ivoire} CI 
{Croatia (local name: Hrvatska)} HR Cuba CU Cyprus CY {Czech Republic} CZ Denmark DK Djibouti DJ Dominica DM 
{Dominican Republic} DO {East Timor} TP Ecuador EC Egypt EG {El Salvador} SV {Equatorial Guinea} GQ Eritrea ER 
Estonia EE Ethiopia ET {Falkland Islands (Malvinas)} FK {Faroe Islands} FO Fiji FJ Finland FI France FR 
{France, Metropolitan} FX {French Guiana} GF {French Polynesia} PF {French Southern Territories} TF Gabon GA 
Gambia GM Georgia GE Germany DE Ghana GH Gibraltar GI Greece GR Greenland GL Grenada GD Guadeloupe GP Guam GU 
Guatemala GT Guinea GN Guinea-Bissau GW Guyana GY Haiti HT {Heard and Mc Donald Islands} HM 
{Holy See (Vatican City State)} VA Honduras HN {Hong Kong} HK Hungary HU Iceland IS India IN Indonesia ID 
{Iran (Islamic Republic of)} IR Iraq IQ Ireland IE Israel IL Italy IT Jamaica JM Japan JP Jordan JO Kazakhstan KZ 
Kenya KE Kiribati KI {Korea, Democratic People's Republic of} KP {Korea, Republic of} KR Kuwait KW Kyrgyzstan KG 
{Lao People's Democratic Republic} LA Latvia LV Lebanon LB Lesotho LS Liberia LR {Libyan Arab Jamahiriya} LY 
Liechtenstein LI Lithuania LT Luxembourg LU Macau MO {Macedonia, The Former Yugoslav Republic of} MK Madagascar MG 
Malawi MW Malaysia MY Maldives MV Mali ML Malta MT {Marshall Islands} MH Martinique MQ Mauritania MR Mauritius MU 
Mayotte YT Mexico MX {Micronesia, Federated States of} FM {Moldova, Republic of} MD Monaco MC Mongolia MN 
Montserrat MS Morocco MA Mozambique MZ Myanmar MM Namibia NA Nauru NR Nepal NP Netherlands NL {Netherlands Antilles} AN 
{New Caledonia} NC {New Zealand} NZ Nicaragua NI Niger NE Nigeria NG Niue NU {Norfolk Island} NF 
{Northern Mariana Islands} MP Norway NO Oman OM Pakistan PK Palau PW {Palestinian Territory, occupied} PS Panama PA 
{Papua New Guinea} PG Paraguay PY Peru PE Philippines PH Pitcairn PN Poland PL Portugal PT {Puerto Rico} PR Qatar QA 
Reunion RE Romania RO {Russian Federation} RU Rwanda RW {Saint Kitts and Nevis} KN {Saint Lucia} LC {
Saint Vincent and the Grenadines} VC Samoa WS {San Marino} SM {Sao Tome and Principe} ST {Saudi Arabia} SA 
Senegal SN Seychelles SC {Sierra Leone} SL Singapore SG {Slovakia (Slovak Republic)} SK Slovenia SI 
{Solomon Islands} SB Somalia SO {South Africa} ZA {South Georgia and the South Sandwich Islands} GS Spain ES 
{Sri Lanka} LK {St. Helena} SH {St. Pierre and Miquelon} PM Sudan SD Suriname SR {Svalbard and Jan Mayen Islands} SJ 
Swaziland SZ Sweden SE Switzerland CH {Syrian Arab Republic} SY {Taiwan, Province of China} TW Tajikistan TJ 
{Tanzania, United Republic of} TZ Thailand TH Togo TG Tokelau TK Tonga TO {Trinidad and Tobago} TT Tunisia TN 
Turkey TR Turkmenistan TM {Turks and Caicos Islands} TC Tuvalu TV Uganda UG Ukraine UA {United Arab Emirates} AE 
{United Kingdom} GB {United States} US {United States Minor Outlying Islands} UM Uruguay UY Uzbekistan UZ Vanuatu VU 
Venezuela VE {Viet Nam} VN {Virgin Islands (british)} VG {Virgin Islands (U.S.)} VI {Wallis and Futuna Islands} WF 
{Western Sahara} EH Yemen YE Yugoslavia YU Zambia ZM Zimbabwe ZW
}


namespace eval openssl {
    
    variable cmd
    variable config_file
    variable common_errors

    variable iso3166   ;# contains all iso country codes
    
    set cmd(_signroot) {openssl req -new -x509 -days 3650 -config config.cfg -key ca.key -passin pass:$attr(*password) -out ca.crt}
    set cmd(_srv_sign) {openssl ca -batch -notext -passin pass:$attr(*password) -config config.cfg -out $attr(fn).crt -infiles $attr(fn).csr}
    set cmd(_client_sign) {openssl ca -batch -notext -passin pass:$attr(*password) -config config.cfg -out $attr(fn).crt -infiles $attr(fn).csr}
    set cmd(_client_revoke) {openssl ca -config config.cfg -passin pass:$attr(*password) -revoke $attr(fn).crt}
    set cmd(_export_pkcs12) {openssl pkcs12 -export -in "$attr(fn).crt" -inkey "$attr(fn).key" -certfile ca.crt -name "$attr(username)" -caname "$attr(caname)" -out "$attr(fn).p12" -passout pass:$attr(*password)}
    set cmd(_gencrl) {openssl ca -config config.cfg -gencrl -passin pass:$attr(*password) | openssl crl -outform DER -out "$attr(fn).crl"}
    set cmd(_cert_revoke) {openssl ca -config config.cfg -passin pass:$attr(*password) -revoke $attr(fn)}
    set cmd(newroot) {openssl genrsa -des3 -passout pass:$attr(*password) -out ca.key 1024}
    set cmd(signroot) {openssl req -new -x509 -days 3650 -config config.cfg -key ca.key -passin env:password -out ca.crt}
    set cmd(srv_key) {openssl genrsa -out $attr(fn).key 1024}
    set cmd(srv_req) {openssl req -new -config config.cfg -key $attr(fn).key -out $attr(fn).csr}
    set cmd(srv_sign) {openssl ca -batch -notext -passin env:password -config config.cfg -out $attr(fn).crt -infiles $attr(fn).csr}
    set cmd(srv_revoke) {openssl ca -config config.cfg -passin pass:$attr(*password) -revoke $attr(fn).crt}
    set cmd(client_key) {openssl genrsa -out $attr(fn).key 1024}
    set cmd(client_req) {openssl req -new -config config.cfg -key $attr(fn).key -out $attr(fn).csr}
    set cmd(client_sign) {openssl ca -batch -notext -passin env:password -config config.cfg -out $attr(fn).crt -infiles $attr(fn).csr}
    set cmd(client_revoke) {openssl ca -config config.cfg -passin env:password -revoke $attr(fn).crt}
    set cmd(export_pkcs12) {openssl pkcs12 -export -in "$attr(fn).crt" -inkey "$attr(fn).key" -certfile ca.crt -name "$attr(username)" -caname "$attr(caname)" -out "$attr(fn).p12" -passout env:password}
    set cmd(gencrl) {openssl ca -config config.cfg -gencrl -passin env:password | openssl crl -outform DER -out "$attr(fn).crl"}
    set cmd(cert_revoke) {openssl ca -config config.cfg -passin env:password -revoke $attr(fn)}
    set cmd(cert_view) {openssl x509 -text -in $attr(fn)}

    set cmd(csr_read) {openssl req -text -in "$filename" -out "req.txt"}
    set cmd(crt_read) {openssl x509 -noout -subject -in "$filename"}

    
set config_file(rootca) {
[ req ]
default_bits			= 4096
default_keyfile			= ca.key
distinguished_name		= req_distinguished_name
x509_extensions			= v3_ca
string_mask			= nombstr
req_extensions			= v3_req
prompt				= no
[ req_distinguished_name ]
$attr(all)
[ v3_ca ]
basicConstraints		= critical,CA:true
subjectKeyIdentifier		= hash
[ v3_req ]
nsCertType			= objsign,email,server
}

set config_file(newserver) {
[ req ]
default_bits			= 2048
default_keyfile			= server.key
distinguished_name		= req_distinguished_name
string_mask			= nombstr
req_extensions			= v3_req
prompt                          = no
[ req_distinguished_name ]
countryName			= $attr(C)
stateOrProvinceName		= $attr(ST)
localityName			= $attr(L)
0.organizationName		= $attr(O)
organizationalUnitName		= $attr(OU)
commonName			= $attr(CN)
emailAddress			= $attr(emailAddress)
[ v3_req ]
nsCertType			= server
basicConstraints		= critical,CA:false
}

set config_file(signserver) {
[ ca ]
default_ca              = default_CA
[ default_CA ]
dir                     = .
certs                   = .
new_certs_dir           = ./ca.db.certs
database                = ./ca.db.index
serial                  = ./ca.db.serial
RANDFILE                = ./random-bits
certificate             = ./ca.crt
private_key             = ./ca.key
default_days            = 365
default_crl_days        = 30
default_md              = md5
preserve                = no
x509_extensions		= server_cert
policy                  = policy_anything
[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName              = supplied
emailAddress            = optional
[ server_cert ]
#subjectKeyIdentifier	= hash
authorityKeyIdentifier	= keyid:always
extendedKeyUsage	= serverAuth,clientAuth,msSGC,nsSGC
basicConstraints	= critical,CA:false
}

set config_file(newclient) {
[ req ]
default_bits			= 2048
default_keyfile			= user.key
distinguished_name		= req_distinguished_name
string_mask			= nombstr
req_extensions			= v3_req
prompt                          = no
[ req_distinguished_name ]
commonName			= $attr(CN)
emailAddress			= $attr(emailAddress)
[ v3_req ]
nsCertType			= client,email
basicConstraints		= critical,CA:false
}

set config_file(signclient) {
[ ca ]
default_ca              = default_CA
[ default_CA ]
dir                     = .
certs                   = .
new_certs_dir           = ./ca.db.certs
database                = ./ca.db.index
serial                  = ./ca.db.serial
RANDFILE                = ./random-bits
certificate             = ./ca.crt
private_key             = ./ca.key
default_days            = 365
default_crl_days        = 30
default_md              = md5
preserve                = yes
x509_extensions		= client_cert
policy                  = policy_anything
[ policy_anything ]
commonName              = supplied
emailAddress            = supplied
[ client_cert ]
#SXNetID		= 3:yeak
subjectAltName		= email:copy
basicConstraints	= critical,CA:false
authorityKeyIdentifier	= keyid:always
extendedKeyUsage	= clientAuth,emailProtection,codeSigning,msCodeInd,msCodeCom
}


    # list of common_errors
    # contains pairs of values
    # error pattern (regexp) followed by explanation.
    # used by openssl::CheckCommonErrors
    set common_errors {
	"ERROR:There is already a certificate" "Can not sign certificate request.\n\nValid Certificate already exists in database with identical subject."
	"problems making Certificate Request" "Could not make Certificate Request.\n\nPlease check fields : country code should have 2 characters, other fields are maximal 40 chars."
	"unable to load CA private key" "Unable to load CA private key.\n\nPlease verify that you typed the passphrase was correct."
	":system library:fopen:No such file or directory" "No such file or directory.\n\nPlease verify file name."
	"unable to load X509 request" "Unable to load certificate request.\n\nPlease check that the file has correct format."
	"Error loading certificates from input" "Unable to load certificate.\n\nPlease check that the certificate file is not damaged."
	"ERROR:Already revoked" "Certificate has already been revoked before"
}


}


proc openssl::GenerateConfigAttributes {attr} {
    upvar $attr attributes
    
    set retval ""
    foreach v {C ST L O OU CN emailAddress} {
	if {[info exists attributes($v)]} {
	    if {$attributes($v) != ""} {
		append retval "$v\t\t= $attributes($v)\n"
	    }
	}
    }
    
    return $retval
}


proc openssl::_CSR_GetCommonName {filename} {

    debug::msg "openssl::CSRGetCommonName $filename" 2
    
    set cmd(read_req) {openssl req -text -in "$filename.crt" -out "req.txt"}

    catch {eval exec [subst $cmd(read_req)]}
    set f [open "req.txt" r]; set text [read $f] ; close $f

    regsub {.* Subject: CN=} $text {} text
    regsub {/Email.*} $text {} text
    
    catch {file delete "req.txt"}

    return $text
}

proc openssl::CSR_GetSubject {filename} {
    
    debug::msg "openssl::CSR_GetSubject $filename" 2

    set cmd(read_req) {openssl req -text -in "$filename" -out "req.txt"}

    catch {eval exec [subst $cmd(read_req)]}
    set f [open "req.txt" r]; set text [read $f] ; close $f

    regsub {.* Subject:} $text {} text
    regsub {\n.*} $text {} text
    
    catch {file delete "req.txt"}

    return [Cert_ParseSubject $text]
}

proc openssl::CSR_GetType {filename} {
    
    debug::msg "openssl::CSR_GetType $filename" 2

    set cmd(read_req) {openssl req -text -in "$filename" -out "req.txt"}

    catch {eval exec [subst $cmd(read_req)]}
    set f [open "req.txt" r]; set text [read $f] ; close $f

    if {[regexp {.*Netscape Cert Type:} $text]} {
	regsub {.*Netscape Cert Type:} $text {} text
	regsub {X509v3 Basic Constraints:.*} $text {} text
	set text [string trim $text]
    } else {
	set text "?"
    }
    

    # puts "found type $text"
    catch {file delete "req.txt"}

    return [list Type $text]
}



proc openssl::Cert_ParseSubject {subject} {

    debug::msg "openssl::Cert_ParseSubject \"$subject\"" 2

    set result {}
    
    foreach sub [split $subject / ] {
	foreach s [split $sub , ] {
	    set v [split $s =]; set v0 [string trim [lindex $v 0]]; set v1 [string trim [lindex $v 1]]
	    lappend result $v0 $v1
	}
    }

    return $result
}


proc openssl::CRT_GetSubject {filename} {
 
    debug::msg "openssl::CRT_GetSubject $filename" 2
	
    set cmd(read_req) {openssl x509 -noout -subject -in "$filename"}

    set text [eval exec [subst $cmd(read_req)]]
    regsub {^subject=} $text {} text
    set text [string trim $text]
    
    return [Cert_ParseSubject $text]
}



# proc openssl::do action config attributes
# action :
#   newroot, signroot
#   srv_key, srv_req, srv_sign, srv_revoke
#   client_key, client_req, client_sign, client_revoke, export_pkcs12
#   gencrl
#   cert_revoke, cert_view
# config :
#   rootca
#   newserver
#   signserver
#   newclient
#   signclient
# attributes : array of
#   C
#   ST
#   L
#   O
#   OU
#   CN
#   emailAddress
#
proc openssl::do {action config attributes} {

    variable config_file
    variable cmd
    
    upvar $attributes attr
    
    debug::msg "openssl::do \"$action\" \"$config\" \"$attributes\""

    if {$config != ""} {
	set f [open "config.cfg" w]
	puts $f [subst -nocommands -nobackslashes $config_file($config)]
	close $f
    }
    
    if {[info exists attr(*password)]} {
    	global env    
	set env(password) $attr(*password)
    }
    
    # attributes are in attr() array
    # $attr(all) is list of only set attributes for inclusion in config file
    set attr(all) [GenerateConfigAttributes attr]

    set command [subst $cmd($action)]
    Log::LogMessage "\[OPENSSL\] $command" bold
    set err [catch {eval exec $command} result]
    Log::LogMessage "\[OPENSSL\] result=$err"
    Log::LogMessage "$result"
    Log::LogMessage ""

    # check for common error conditions
    set errmsg [CheckCommonErrors $result]
    if {$errmsg != ""} {
	tk_messageBox -icon error -type ok -title Error -message "$errmsg"
    }
    
    
    if {[info exists attr(*password)]} {
    	global env    
	set env(password) ""
    }

    if {$action == "srv_revoke" && [file exists "ca.db.index.new"]} {
	file rename -force "ca.db.index.new" "ca.db.index"
    }

    if {$action == "cert_revoke" && [file exists "ca.db.index.new"]} {
	file rename -force "ca.db.index.new" "ca.db.index"
    }

    if {$config != ""} {
	catch {file delete "config.cfg"}
    }
    
}


proc openssl::CheckCommonErrors {result_text} {
    
    variable common_errors

    debug::msg "openssl::CheckCommonErrors \"$result_text\"" 2

    set ret_code ""
    
    foreach {code explanation} $common_errors {
	if {[regexp $code $result_text]} {
	    set ret_code $explanation
	    break
	}	
    }
    
    return $ret_code
}


proc openssl::_GetIso3166 {} {

    variable iso3166
    variable iso3166_map
    
    catch {unset iso3166}
    catch {unset iso3166_map}
    set f [open "D:/Devel/SimpleCA/v1/iso3166.txt" "r"]
    while {[gets $f line] != -1} {
	set long [string trim [string range $line 0 47]]
	set short [string range $line 48 49]
	lappend iso3166 $long
	set iso3166_map($short) "$long"
	set iso3166_map($long) "$short"
    }
    close $f
}

proc openssl::GetIso3166 {} {

    global g_iso3166_codes
    variable iso3166
    variable iso3166_map
    
    catch {unset iso3166}
    catch {unset iso3166_map}
    foreach {long short} $g_iso3166_codes {
	lappend iso3166 $long
	set iso3166_map($short) "$long"
	set iso3166_map($long) "$short"
    }
}

proc openssl::Iso3166Map {v} {

    variable iso3166_map
    
    return $iso3166_map($v)
    
}


#initialisation
openssl::GetIso3166


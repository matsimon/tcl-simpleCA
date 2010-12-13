#
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

source mclistbox.tcl
source ConsoleAux.tcl
source openssl.tcl
source combobox.tcl

set MenuCommands {
   
    #setup {Setup} {
	cmd {Setup Root CA} {cmd::SetupRootCA}
    }
    server {Server Certificates} {
	cmd {New Server Certificate Request} {cmd::NewServerReq}
	cmd {Sign Server Certificate Request} {cmd::SignServerReq}
    }
    client {Client Certificates} {
	cmd {New Client Certificate Request} {cmd::NewClientReq}
	cmd {Sign Client Certificate Request} {cmd::SignClientReq}
	cmd {Export PKCS12 format} {cmd::ExportPKCS12}
    }
    revoke {Revocation} {
	cmd {Revoke Given Certificate} {cmd::RevokeCert}
	cmd {Generate CRL} {cmd::GenerateCRL}
    }
    help {Help} {
	#cmd {Help} {cmd::Help}
	cmd {Readme} {cmd::HelpReadme}
	cmd {About} {cmd::About}
    }
    
}


set config_file(rootca) {
[ req ]
default_bits			= 1024
default_keyfile			= ca.key
distinguished_name		= req_distinguished_name
x509_extensions			= v3_ca
string_mask			= nombstr
req_extensions			= v3_req
prompt				= no
[ req_distinguished_name ]
$attributes
[ v3_ca ]
basicConstraints		= critical,CA:true
subjectKeyIdentifier		= hash
[ v3_req ]
nsCertType			= objsign,email,server
}

set config_file(_rootca) {
[ req ]
default_bits			= 1024
default_keyfile			= ca.key
distinguished_name		= req_distinguished_name
x509_extensions			= v3_ca
string_mask			= nombstr
req_extensions			= v3_req
prompt				= no
[ req_distinguished_name ]
C                      = $attr(C)
ST                     = $attr(ST)
L                      = $attr(L)
O                      = $attr(O)
OU                     = $attr(OU)
CN                     = $attr(CN)
emailAddress           = $attr(emailAddress)
[ v3_ca ]
basicConstraints		= critical,CA:true
subjectKeyIdentifier		= hash
[ v3_req ]
nsCertType			= objsign,email,server
}

set config_file(newserver) {
[ req ]
default_bits			= 1024
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
default_bits			= 1024
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
extendedKeyUsage	= clientAuth,emailProtection
}

proc _GenerateConfigAttributes {attr} {
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


proc  MakeMenu {w label def} {
    
    catch {destroy $w.$label}

    menu $w.$label -tearoff 0
    # puts "command: menu $w.$label -tearoff 0"
    
    foreach {wg text content} $def {
	if {[string index $wg 0] == "#"} {
	    # ignore
	} elseif {$wg == "cmd"} {
	    $w.$label add command -label $text -command $content
	    # puts "command: $w.$label add command -label $text -command $content"
	} else {
	    MakeMenu $w.$label $wg $content
	    $w.$label add cascade -label $text -menu $w.$label.$wg
	    # puts "command: $w.$label add cascade -label $text -menu $w.$label.$wg"
	}
    }  
}


proc CertificateListBox {w} {

    # this lets us be reentrant...
    #eval destroy [winfo children $w]
    catch {destroy $w}

    # we want the listbox and two scrollbars to be embedded in a 
    #frame $w -bd 2 -relief sunken
    frame $w -bd 2 -relief sunken

    # frame so they look like a single widget
    scrollbar $w.vsb -orient vertical -command [list $w.listbox yview]
    scrollbar $w.hsb -orient horizontal -command [list $w.listbox xview]

    # we will purposefully make the width less than the sum of the
    # columns so that the scrollbars will be functional right off
    # the bat.
    mclistbox::mclistbox $w.listbox \
      -bd 0 \
      -height 10 \
      -width 80 \
      -columnrelief flat \
      -labelanchor w \
      -columnborderwidth 0 \
      -selectmode extended \
      -labelborderwidth 2 \
      -fillcolumn attr \
      -xscrollcommand [list $w.hsb set] \
      -yscrollcommand [list $w.vsb set]
    
    # add the columns we want to see
    $w.listbox column add serial -label "Serial"          -width 8
    $w.listbox column add cn -label "Common Name"          -width 24
    $w.listbox column add email -label "Email"          -width 24
    $w.listbox column add status  -label "Status" -width 8
    $w.listbox column add valid  -label "Valid Until" -width 16
    $w.listbox column add attr  -label "Attributes" -width 128
    
    # set up bindings to sort the columns.
    $w.listbox label bind serial <ButtonPress-1> "sort %W serial"
    $w.listbox label bind cn <ButtonPress-1> "sort %W cn"
    $w.listbox label bind email <ButtonPress-1> "sort %W email"
    $w.listbox label bind status  <ButtonPress-1> "sort %W status"
    $w.listbox label bind valid  <ButtonPress-1> "sort %W valid"
    $w.listbox label bind attr  <ButtonPress-1> "sort %W attr"
    
    grid $w.vsb -in $w -row 0 -column 1 -sticky ns
    grid $w.hsb -in $w -row 1 -column 0 -sticky ew
    grid $w.listbox -in $w -row 0 -column 0 -sticky nsew -padx 0 -pady 0
    grid columnconfigure $w 0 -weight 1
    grid columnconfigure $w 1 -weight 0
    grid rowconfigure    $w 0 -weight 1
    grid rowconfigure    $w 1 -weight 0
    
    # pack .container -side top -fill both -expand y
    bind $w.listbox <ButtonPress-3> \
      {showContextMenu \
      [::mclistbox::convert %W -W] \
      [::mclistbox::convert %W -x %x] \
      [::mclistbox::convert %W -y %y] \
      %X %Y}

    return $w
    
}


proc showContextMenu {w x y rootx rooty} {
    
    set s {}
    foreach i [$w curselection] {
	lappend s [lindex [$w get $i] 0]
    }
    
    if {$s != ""} {

	catch {destroy .contextMenu}
	menu .contextMenu -tearoff false
		
	.contextMenu configure -title "Certificate"
	#.contextMenu add command \
	#  -label "View" \
	#  -command [list cmd::ViewCertificate $s]
	.contextMenu add command \
	  -label "View" \
	  -command [list cmd::ViewByIndex $s]
	.contextMenu add command \
	  -label "Revoke" \
	  -command [list cmd::RevokeCertByIndex $s]
	
	tk_popup .contextMenu $rootx $rooty
	
    }
    
}



#
# Logging Window
#

namespace eval Log {
    
    #namespace export LogWindow;		# Initialization
    
    namespace export toggle;	# Command to map/unmap the
    # console on demand
    
    variable mapped;		# Flag == 1 iff the console
    array set mapped {}
    
    
    variable logwindow
    variable filename
    variable logchannel
    
}



proc Log::CreateWindow {w} {

    variable mapped
    
    # this lets us be reentrant...
    catch {destroy $w}
    toplevel $w
    wm title $w "Message Log"
    
    # we want the listbox and two scrollbars to be embedded in a 
    #frame $w -bd 2 -relief sunken
    pack [frame $w.f -bd 2 -relief sunken] -expand 1 -fill both

    # frame so they look like a single widget
    scrollbar $w.f.vsb -orient vertical -command [list $w.f.text yview]
    scrollbar $w.f.hsb -orient horizontal -command [list $w.f.text xview]

    # we will purposefully make the width less than the sum of the
    # columns so that the scrollbars will be functional right off
    # the bat.
    text $w.f.text \
      -bd 0 \
      -height 10 \
      -width 80 \
      -wrap none \
      -xscrollcommand [list $w.f.hsb set] \
      -yscrollcommand [list $w.f.vsb set]
    
    grid $w.f.vsb -in $w.f -row 0 -column 1 -sticky ns
    grid $w.f.hsb -in $w.f -row 1 -column 0 -sticky ew
    grid $w.f.text -in $w.f -row 0 -column 0 -sticky nsew -padx 0 -pady 0
    grid columnconfigure $w.f 0 -weight 1
    grid columnconfigure $w.f 1 -weight 0
    grid rowconfigure    $w.f 0 -weight 1
    grid rowconfigure    $w.f 1 -weight 0
    
    # hide window in stead of closing.
    #wm protocol $w WM_DELETE_WINDOW "wm withdraw $w"
    wm protocol $w WM_DELETE_WINDOW "Log::WindowToggle $w"
    
    # start hidden
    wm withdraw $w
    set mapped($w) 0
    
    #tags
    $w.f.text tag configure normal -font {{MS Sans Serif} 8}
    $w.f.text tag configure bold -font {{MS Sans Serif} 8 bold}
    $w.f.text tag configure blue -foreground {blue}
    
    return $w
    
}

proc Log::WindowToggle {w} {

    variable mapped
    
    if {[wm state $w] != "normal"} {
	wm deiconify $w
	set mapped($w) 1
    } else {
	wm withdraw $w
	set mapped($w) 0
    }
    
}
proc Log::LogMessage {msg {option ""} } {

    variable logwindow
    variable logchannel
    if {[info exists logwindow]} {
	set w $logwindow
	if {$option == ""} {
	    $w.f.text insert end "$msg\n" normal
	} elseif {$option == "bold"} {
	    $w.f.text insert end "$msg\n" bold
	} elseif {$option == "blue"} {
	    $w.f.text insert end "$msg\n" blue
	}
	$w.f.text see end
    }
    
    if {[info exists logchannel]} {
	puts $logchannel $msg
	flush $logchannel
    }

}

proc Log::ToWindow {w} {
    variable logwindow
    
    CreateWindow $w
    set logwindow $w
}

proc Log::ToFile {fn} {
    variable filename
    variable logchannel
    
    set filename $fn
    
    if {[info exists logchannel]} {
	close $logchannel
    }

    
    set logchannel [open $filename "a"]

}

proc Log::Cleanup {} {
    variable logwindow
    variable logchannel
    
    if {[info exists logchannel]} {
	close $logchannel
    }    
}

#
# debugging utilities
# 
namespace eval debug {
    
    namespace export msg      ; # log debug message
    variable level
    set level 0               ; # level :
                                # 0 no debug
                                # 1 medium debug
                                # 2 high debug
}

proc debug::msg {msg {lvl 1}} {
    variable level
    #::LogWindow::LogMessage .log "debug::msg $msg $lvl (level = $level)" blue
    if {$lvl <= $level} {
	::Log::LogMessage "\[DEBUG\] $msg" blue
    }
}


# sort the list based on a particular column
proc sort {w id} {

    set data [$w get 0 end]
    set index [lsearch -exact [$w column names] $id]

    set result [lsort -index $index $data]

    $w delete 0 end

    # ... and add our sorted data in
    eval $w insert end $result

}


# globa inptu
array set input_values {}
array set input_opts {}

# params consists of list of lists
# {name label default opts}
#  name : attribute name
#  label : label to display
#  default : default value
#  opts : input options, following are defined
#   * password field (no validation, no echo)
#   ! mandatory (should contain value)
#
proc Dialog_AskAttributes_old {w title params } {

    debug::msg "Dialog_AskAttributes $w $title $params"
    
    global input_values
    array unset input_values
    array set input_values {}
    global input_opts
    array unset input_opts
    array set input_opts {}
    set checks ""
    
    catch {destroy $w}
    toplevel $w
    wm title $w $title
    #frame $w -bd 2 -relief sunken
    #frame $w.attr -bd 2 -relief sunken
    #frame $w.butt -bd 2 -relief sunken
    #frame $w 
    frame $w.attr 
    frame $w.butt 
    pack $w.attr
    pack $w.butt -expand 1 -fill both
    #button $w.butt.ok -text "Ok" -command "if {\[Dialog_CheckInput $w input_values input_opts\]} \"set input_values(exit) ok; destroy $w\" else {bell}"
    #button $w.butt.ok -text "Ok" -command "if {\[Dialog_CheckInput $w $checks\]} \"set input_values(exit) ok; destroy $w\" else {bell}"
    #button $w.butt.cancel -text "Cancel" -command "set input_values(exit) cancel; destroy $w"
    #pack $w.butt.ok $w.butt.cancel -side left -expand 1 -fill both
    
    set checks ""
    set i 0
    grid rowconfigure $w.attr $i -weight 0 -minsize 20
    incr i
    foreach {p label deflt opts} $params {
	set input_values($p) $deflt
	set input_opts($p) $opts
	lappend checks $p
	lappend checks $label
	label $w.attr.label_$i -text $label
	if {[string index $p 0] == "*"} {
	    # password field
	    entry $w.attr.entry_$i -textvariable input_values($p) -width 40 -show *
	} else {
	    # normal field
	    entry $w.attr.entry_$i -textvariable input_values($p) -width 40 -validate key -vcmd "Dialog_Validate %S \"before=%s, after=%P\"" -invcmd "bell"
	}
    
	grid $w.attr.label_$i -in $w.attr -row $i -column 0 -sticky nw
	grid $w.attr.entry_$i -in $w.attr -row $i -column 1 -sticky nw
	grid rowconfigure $w.attr $i -weight 0 -minsize 2
	incr i
    }
    button $w.butt.ok -text "Ok" -command "if {\[Dialog_CheckInput $w \"$checks\"\]} \"set input_values(exit) ok; destroy $w\" else {bell}"
    button $w.butt.cancel -text "Cancel" -command "set input_values(exit) cancel; destroy $w"
    pack $w.butt.ok $w.butt.cancel -side left -expand 1 -fill both

    grid rowconfigure $w.attr $i -weight 0 -minsize 20
    grid columnconfigure $w.attr 0 -weight 0 -minsize 2
    grid columnconfigure $w.attr 1 -weight 0 -minsize 2
    
    grab set $w
    tkwait window $w
    return [array get input_values]
}

# Dialog_AskAttributes w title params
# params consists of list of lists
# {name label default opts}
# {name label default {c choices}}
#  name : attribute name
#  label : label to display
#  default : default value
#  opts : input options, following are defined
#   * password field (no validation, no echo)
#   ! mandatory (should contain value)
#   c combobox, in this case opts is contains opts + global with valid entries
# choices : if emtpy : normal entry box
# if non-empty : drop down with valid choices
# choices are in global array with name in this field
#
proc Dialog_AskAttributes {w title params } {

    debug::msg "Dialog_FancyAskAttributes $w $title $params"
    
    global input_values
    array unset input_values
    array set input_values {}
    global input_opts
    array unset input_opts
    array set input_opts {}
    set checks ""
    
    catch {destroy $w}
    toplevel $w
    wm title $w $title
    frame $w.attr 
    frame $w.butt 
    pack $w.attr
    pack $w.butt -expand 1 -fill both
    
    set checks ""
    set i 0
    grid rowconfigure $w.attr $i -weight 0 -minsize 20
    incr i
    foreach {p label deflt opts} $params {
	set input_values($p) $deflt
	set input_opts($p) [lindex $opts 0]
	lappend checks $p
	lappend checks $label
	label $w.attr.label_$i -text $label
	if {[string first "c" [lindex $opts 0]] != -1} {
	    # combo box
	    combobox::combobox $w.attr.entry_$i -textvariable input_values($p) -width 37 -editable 0
	    
	    # now add all options
	    set valid_choices_var [lindex $opts 1]
	    upvar #0 $valid_choices_var valid_choices
	    foreach v $valid_choices {
		$w.attr.entry_$i list insert end $v
	    }
	    
	    # set default
	    $w.attr.entry_$i select [lsearch -exact $valid_choices $deflt]
	    
	    # if not mandatory : allow empty option
	    if {[string first "!" [lindex $opts 0]] == -1} {
		$w.attr.entry_$i list insert 0 ""		
	    }
	    
	} else {
	    # normal input field
	    if {[string index $p 0] == "*"} {
		# password field
		entry $w.attr.entry_$i -textvariable input_values($p) -width 40 -show *
	    } else {
		# normal field
		entry $w.attr.entry_$i -textvariable input_values($p) -width 40 -validate key -vcmd "Dialog_Validate %S \"before=%s, after=%P\"" -invcmd "bell"
	    }
	    
	}
	

	grid $w.attr.label_$i -in $w.attr -row $i -column 0 -sticky nw
	grid $w.attr.entry_$i -in $w.attr -row $i -column 1 -sticky nw
	grid rowconfigure $w.attr $i -weight 0 -minsize 2
	incr i
    }
    button $w.butt.ok -text "Ok" -command "if {\[Dialog_CheckInput $w \"$checks\"\]} \"set input_values(exit) ok; destroy $w\" else {bell}"
    button $w.butt.cancel -text "Cancel" -command "set input_values(exit) cancel; destroy $w"
    pack $w.butt.ok $w.butt.cancel -side left -expand 1 -fill both

    grid rowconfigure $w.attr $i -weight 0 -minsize 20
    grid columnconfigure $w.attr 0 -weight 0 -minsize 2
    grid columnconfigure $w.attr 1 -weight 0 -minsize 2
    
    # do not allow closing via [x] button
    wm protocol $w WM_DELETE_WINDOW ";"
    
    # now get input
    grab set $w
    tkwait window $w
    return [array get input_values]
}

array set dialog_labels {
	C {Country}
	ST {State or Province}
	L {Locality or City}
	O {Organization}
	OU {Organizational Unit}
	CN {Common Name}
	emailAddress {Email}
	Email {Email}
	Type {Certificate Type}
}

proc Dialog_ConfirmAttributes {w title params } {

    debug::msg "Dialog_ConfirmAttributes $w $title $params"
    
    global input_values
    global dialog_labels
    array unset input_values
    array set input_values {}
    
    catch {destroy $w}
    toplevel $w
    wm title $w $title

    frame $w.attr 
    frame $w.butt 
    pack $w.attr
    pack $w.butt -expand 1 -fill both
    button $w.butt.ok -text "Ok" -command "set input_values(exit) ok; destroy $w"
    button $w.butt.cancel -text "Cancel" -command "set input_values(exit) cancel; destroy $w"
    pack $w.butt.ok $w.butt.cancel -side left -expand 1 -fill both
    
    set i 0
    grid rowconfigure $w.attr $i -weight 0 -minsize 20
    incr i
    foreach {p deflt} $params {
	set input_values($p) $deflt
	label $w.attr.label_$i -text $dialog_labels($p)
	entry $w.attr.entry_$i -textvariable input_values($p) -width 40 -state disabled

	grid $w.attr.label_$i -in $w.attr -row $i -column 0 -sticky nw
	grid $w.attr.entry_$i -in $w.attr -row $i -column 1 -sticky nw
	grid rowconfigure $w.attr $i -weight 0 -minsize 2

	incr i
    }
    grid rowconfigure $w.attr $i -weight 0 -minsize 20
    grid columnconfigure $w.attr 0 -weight 0 -minsize 2
    grid columnconfigure $w.attr 1 -weight 0 -minsize 2

    # do not allow closing via [x] button
    wm protocol $w WM_DELETE_WINDOW ";"
    
    # now get input
    grab set $w
    tkwait window $w
    return $input_values(exit)
}


proc Dialog_Validate {s {comment ""}} {
    
    debug::msg "Dialog_Validate $s (comment: $comment)" 2

    set retval [regexp {^[\w\s\.@-]*$} $s]
    #puts " -> returns $retval"
    return $retval
}

proc Dialog_CheckInput {w checks} {

    global input_values
    global input_opts
    
    debug::msg "Dialog_CheckInput $w $checks" 2

    set password ""
    set password_repeat ""
    foreach {name label} $checks {
	set value $input_values($name)
	if {[string first ! $input_opts($name)] != -1} {
	    if {$value == ""} {
		update
		tk_messageBox -title "Warning" -parent $w -icon info -type ok -message "Please provide a value for field: $label"
		return 0
	    }
	}
    
    }
    
    # if password & repeat password fields : check equal
    #if {[info exists arr(*password)] && [info exists arr(*again)] && $arr(*password) != $arr(*again)} {
    #	    update
    #	    tk_messageBox -title "Warning" -parent $w -icon info -type ok -message "Passwords differ."
    #	    return 0
    #}
    
    # if password & repeat password fields : check equal
    if {[info exists input_values(*password)] && [info exists input_values(*again)] && $input_values(*password) != $input_values(*again)} {
	    update
	    tk_messageBox -title "Warning" -parent $w -icon info -type ok -message "Passwords differ."
	    return 0
    }
    
    return 1
}

proc __Dialog_CheckInput {w v opts} {
    #puts "CheckInput $v"
    upvar $v arr
    upvar $opts opts_arr
    #puts "[array get arr]"
    foreach {name value} [lsort [array get arr]] {
	if {$value == ""} {
	    update
	    tk_messageBox -title "Warning" -parent $w -icon info -type ok -message "Please provide a value for all fields"
	    return 0
	}
    }
    
    # if password & repeat password fields : check equal
    if {[info exists arr(*password)] && [info exists arr(*again)] && $arr(*password) != $arr(*again)} {
	    update
	    tk_messageBox -title "Warning" -parent $w -icon info -type ok -message "Passwords differ."
	    return 0
    }
    
    return 1
}

proc GetCertificates {w filename} {

    debug::msg "GetCertificates $w $filename"
    
    $w.listbox delete 0 end
    
    set f [open $filename r]
    
    while {[gets $f line] != -1} {
	set v [split $line \t]
	set status [lindex $v 0]
	set serial [lindex $v 3]
	set validity [lindex $v 1]
	set t [lindex $v 1]
	set date [clock format [clock scan "[string range $t 0 1]-[string range $t 2 3]-[string range $t 4 5] [string range $t 6 7]:[string range $t 8 9]"] -format "%d/%m/%Y %H:%M"]
	set attributes [lindex $v 5]
	set v [lrange [split $attributes /=] 1 end]
	foreach {label cn} $v { if {$label == "CN"} break}
	# cn contains now common name

	foreach {label email} $v { if {$label == "Email"} break}
	# email contains now email
	#$w.listbox insert end [list $serial $cn $email $status $validity $attributes]
	$w.listbox insert end [list $serial $cn $email $status $date $attributes]
 
    }
    
    close $f
}

proc _CSRGetCommonName {filename} {

    debug::msg "proc CSRGetCommonName $filename" 2
    
    set cmd(read_req) {openssl req -text -in "$filename.crt" -out "req.txt"}

    catch {eval exec [subst $cmd(read_req)]}
    set f [open "req.txt" r]; set text [read $f] ; close $f

    regsub {.* Subject: CN=} $text {} text
    regsub {/Email.*} $text {} text
    
    catch {file delete "req.txt"}

    return $text
}

proc __ParseSubject {subject v} {

    upvar $v arr
    #array unset arr
    #array set arr {}
    
    foreach sub [split $subject / ] {
	foreach s [split $sub , ] {
	    set v [split $s =]; set v0 [string trim [lindex $v 0]]; set v1 [string trim [lindex $v 1]]
	    set arr($v0) $v1	    
	}
    }

}

proc _CertParseSubject {subject} {

    set result {}
    
    foreach sub [split $subject / ] {
	foreach s [split $sub , ] {
	    set v [split $s =]; set v0 [string trim [lindex $v 0]]; set v1 [string trim [lindex $v 1]]
	    lappend result $v0 $v1
	}
    }

    return $result
}

proc _CSRGetSubject {filename} {
    
    set cmd(read_req) {openssl req -text -in "$filename" -out "req.txt"}

    catch {eval exec [subst $cmd(read_req)]}
    set f [open "req.txt" r]; set text [read $f] ; close $f

    regsub {.* Subject:} $text {} text
    regsub {\n.*} $text {} text
    
    catch {file delete "req.txt"}

    return [CertParseSubject $text]
}

proc _CRTGetSubject {filename} {
    
    set cmd(read_req) {openssl x509 -noout -subject -in "$filename"}

    set text [eval exec [subst $cmd(read_req)]]
    regsub {^subject=} $text {} text
    set text [string trim $text]
    
    return [CertParseSubject $text]
}

proc _CSRGetType {filename} {
    
    #puts "CSRGetType $filename"
    set cmd(read_req) {openssl req -text -in "$filename" -out "req.txt"}

    catch {eval exec [subst $cmd(read_req)]}
    set f [open "req.txt" r]; set text [read $f] ; close $f

    regsub {.*Netscape Cert Type:} $text {} text
    regsub {X509v3 Basic Constraints:.*} $text {} text
    set text [string trim $text]
    # puts "found type $text"
    catch {file delete "req.txt"}

    return [list Type $text]
}


namespace eval cmd {
    variable _cmd
    set _cmd(_signroot) {openssl req -new -x509 -days 3650 -config config.cfg -key ca.key -passin pass:$attr(*password) -out ca.crt}
    set _cmd(_srv_sign) {openssl ca -batch -notext -passin pass:$attr(*password) -config config.cfg -out $attr(fn).crt -infiles $attr(fn).csr}
    set _cmd(_client_sign) {openssl ca -batch -notext -passin pass:$attr(*password) -config config.cfg -out $attr(fn).crt -infiles $attr(fn).csr}
    set _cmd(_client_revoke) {openssl ca -config config.cfg -passin pass:$attr(*password) -revoke $attr(fn).crt}
    set _cmd(_export_pkcs12) {openssl pkcs12 -export -in "$attr(fn).crt" -inkey "$attr(fn).key" -certfile ca.crt -name "$attr(username)" -caname "$attr(caname)" -out "$attr(fn).p12" -passout pass:$attr(*password)}
    set _cmd(_gencrl) {openssl ca -config config.cfg -gencrl -passin pass:$attr(*password) | openssl crl -outform DER -out "$attr(fn).crl"}
    set _cmd(_cert_revoke) {openssl ca -config config.cfg -passin pass:$attr(*password) -revoke $attr(fn)}
    set _cmd(newroot) {openssl genrsa -des3 -passout pass:$attr(*password) -out ca.key 1024}
    set _cmd(signroot) {openssl req -new -x509 -days 3650 -config config.cfg -key ca.key -passin env:password -out ca.crt}
    set _cmd(srv_key) {openssl genrsa -out $attr(fn).key 1024}
    set _cmd(srv_req) {openssl req -new -config config.cfg -key $attr(fn).key -out $attr(fn).csr}
    set _cmd(srv_sign) {openssl ca -batch -notext -passin env:password -config config.cfg -out $attr(fn).crt -infiles $attr(fn).csr}
    set _cmd(srv_revoke) {openssl ca -config config.cfg -passin pass:$attr(*password) -revoke $attr(fn).crt}
    set _cmd(client_key) {openssl genrsa -out $attr(fn).key 1024}
    set _cmd(client_req) {openssl req -new -config config.cfg -key $attr(fn).key -out $attr(fn).csr}
    set _cmd(client_sign) {openssl ca -batch -notext -passin env:password -config config.cfg -out $attr(fn).crt -infiles $attr(fn).csr}
    set _cmd(client_revoke) {openssl ca -config config.cfg -passin env:password -revoke $attr(fn).crt}
    set _cmd(export_pkcs12) {openssl pkcs12 -export -in "$attr(fn).crt" -inkey "$attr(fn).key" -certfile ca.crt -name "$attr(username)" -caname "$attr(caname)" -out "$attr(fn).p12" -passout env:password}
    set _cmd(gencrl) {openssl ca -config config.cfg -gencrl -passin env:password | openssl crl -outform DER -out "$attr(fn).crl"}
    set _cmd(cert_revoke) {openssl ca -config config.cfg -passin env:password -revoke $attr(fn)}
    set _cmd(cert_view) {openssl x509 -text -in $attr(fn)}
    
}


proc cmd::_openssl {action} {


    Log::LogMessage "\[CMD::OPENSSL\]$action" bold
    set err [catch {eval exec $action} result]
    Log::LogMessage "\[CMD::OPENSSL\]result=$err"
    Log::LogMessage "$result"
    Log::LogMessage ""
    
}


proc cmd::SetupRootCA {} {
    
    debug::msg "cmd::SetupRootCA"
    
    #now in openssl::
    #variable cmd
    #global config_file
    
    # request attributes
    
    set attr(exit) ""
    while {$attr(exit)!="ok"} {

    array set attr [Dialog_AskAttributes .popup {Set Up Root CA} {
	C {Country} {} "c openssl::iso3166"
	ST {State or Province Name (full name)} {} ""
	L {Locality Name (eg, City)} {} ""
	O {Organization (eg, company) *} {SimpleCA} "!"
	OU {Organizational Unit (eg, section)} {Demo CA} ""
	CN {Common Name (eg, Root CA) *} {SimpleCA Demo CA} "!"
	emailAddress {Email Address} {democa@democa.com} ""
	*password {CA Key Password} {} "!*"
	*again {Repeat Password} {} "!*" }]


	if {$attr(exit) != "ok"} {
	set answer [tk_messageBox -icon info -type retrycancel -message "You have to generate Root CA certificate before you can use this CA"]
	if {$answer == "cancel"} {
		exit 1
	}
	}

    }
	
    if {$attr(exit) == "ok"} {
	update
	
	# get 2 digit code from long name
	if {$attr(C) != ""} {
	    set attr(C) [openssl::Iso3166Map $attr(C)]
	}

	#set attributes [GenerateConfigAttributes attr]
	
	# create root cert
	openssl::do newroot "" attr
	openssl::do signroot rootca attr
	
	## create root cert
	#set f [open "config.cfg" w]
	#puts $f [subst -nocommands -nobackslashes $config_file(rootca)]
	#close $f
	##catch {eval exec [subst $cmd(newroot)]}
	##catch {eval exec [subst $cmd(signroot)]}
	
	#global env    
	#set env(password) $attr(*password)

	#openssl [subst $cmd(newroot)]
	#openssl [subst $cmd(signroot)]
	#catch {file delete "config.cfg"}
	
	# create database
	file mkdir ca.db.certs
	file mkdir certificates
	close [open "ca.db.index" w+]
	set f [open "ca.db.serial" w+];	puts $f "1000"; close $f
	

    } else {
	update
	tk_messageBox -icon info -type ok -message "You have to generate Root CA certificate before you can use this CA"
	
	# boy this is dirty
	exit 1
    }
	
}



proc cmd::NewServerReq {} {
    
    debug::msg "cmd::NewServerReq"
    
    #now in openssl::
    #variable cmd
    #global config_file
    
    # request attributes
    
    array set attr [Dialog_AskAttributes .popup {New Server Certificate Request} {
	C {Country *} {} "!c openssl::iso3166"
	ST {State or Province Name (full name) *} {} "!"
	L {Locality Name (eg, City) *} {} "!"
	O {Organization (eg, company) *} {} "!"
	OU {Organizational Unit (eg, section) *} {} "!"
	CN {Common Name (eg, www.domain.com) *} {} "!"
	emailAddress {Email Address *} {}  "!"}]
	
    if {$attr(exit) == "ok"} {
	
	set attr(csr_fn) [tk_getSaveFile -defaultextension .csr \
	  -filetypes {
	    {{Certificate Signing Requests} {.csr}}
	    {{All Files} *}
	} \
	  -initialdir certificates \
	  -initialfile $attr(CN).csr \
	  -title "Enter file name to save CSR"]
    }

    if {$attr(exit) == "ok" && $attr(csr_fn) != ""} {

	# get 2 digit code from long name
	if {$attr(C) != ""} {
	    set attr(C) [openssl::Iso3166Map $attr(C)]
	}
	
	# key filename = csr filename, but in stead .key extension.
	regsub {\.csr$} $attr(csr_fn) {} attr(fn)
	#puts "actual file : $attr(fn)"
    
	update
	
	# create server request
	openssl::do srv_key "" attr
	openssl::do srv_req newserver attr
	
	#set f [open "config.cfg" w]
	#puts $f [subst -nocommands -nobackslashes $config_file(newserver)]
	#close $f
	##catch {eval exec [subst $cmd(srv_key)]}
	##catch {eval exec [subst $cmd(srv_req)]}
	#openssl [subst $cmd(srv_key)]
	#openssl [subst $cmd(srv_req)]
	#catch {file delete "config.cfg"}

    } 

}


proc cmd::SignServerReq {} {
    
    debug::msg "cmd::SignServerReq"
    
    #now in openssl::
    #variable cmd    
    #global config_file
    
    # request attributes
    
	
    set csr_fn [tk_getOpenFile -defaultextension .csr \
      -filetypes {
	{{Certificate Signing Requests} {.csr}}
	{{All Files} *}
       } \
      -initialdir certificates \
      -title "Select CSR to sign"]

    if {$csr_fn != "" } {
	set attributes [openssl::CSR_GetSubject $csr_fn]
	set attributes [concat $attributes [openssl::CSR_GetType $csr_fn]]
	set attr(exit) [Dialog_ConfirmAttributes .popup {Do you want to sign this request ?} $attributes]
    }
    
    if {$csr_fn != "" && $attr(exit) == "ok"} {
	array set attr [Dialog_AskAttributes .popup {Sign Server Certificate Request} {
	    *password {CA Key Password}  {}  "!" }]
    }
    
    if {$csr_fn != "" && $attr(exit) == "ok"} {
	
	# key filename = csr filename, but in stead .key extension.
	regsub {\.csr$} $csr_fn {} attr(fn)
	
	update
	
	# sign server request
	openssl::do srv_sign signserver attr
	
	#set f [open "config.cfg" w]
	#puts $f [subst -nocommands -nobackslashes $config_file(signserver)]
	#close $f
	#catch {eval exec [subst $cmd(srv_sign)]}
	
	#global env    
	#set env(password) $attr(*password)

	#openssl [subst $cmd(srv_sign)]
	#catch {file delete "config.cfg"}
    } 

    # reload certificate info
    GetCertificates .main ca.db.index
}


proc cmd::NewClientReq {} {
    
    debug::msg "cmd::NewClientReq"
    
    #now in openssl::
    #variable cmd
    #global config_file
    
    # request attributes
    
    array set attr [Dialog_AskAttributes .popup {New Client Certificate Request} {
	CN {Common Name (eg, John Doe) *} {} "!"
	emailAddress {Email Address *} {} "!" }]
	
    if {$attr(exit) == "ok"} {
	
	set attr(csr_fn) [tk_getSaveFile -defaultextension .csr \
	  -filetypes {
	    {{Certificate Signing Requests} {.csr}}
	    {{All Files} *}
	} \
	  -initialdir certificates \
	  -initialfile $attr(emailAddress).csr \
	  -title "Enter file name to save CSR"]
    }

    if {$attr(exit) == "ok" && $attr(csr_fn) != ""} {
	
	# key filename = csr filename, but in stead .key extension.
	regsub {\.csr$} $attr(csr_fn) {} attr(fn)
	
	update
	
	# create client request
	openssl::do client_key "" attr
	openssl::do client_req newclient attr
	
	#set f [open "config.cfg" w]
	#puts $f [subst -nocommands -nobackslashes $config_file(newclient)]
	#close $f
	##catch {eval exec [subst $cmd(client_key)]}
	##catch {eval exec [subst $cmd(client_req)]}
	#openssl [subst $cmd(client_key)]
	#openssl [subst $cmd(client_req)]
	#catch {file delete "config.cfg"}

    } 

}


proc cmd::SignClientReq {} {
    
    debug::msg "cmd::SignClientReq"
    
    #now in openssl::
    #variable cmd
    #global config_file
    
    # request attributes
    
	
    set csr_fn [tk_getOpenFile -defaultextension .csr \
      -filetypes {
	{{Certificate Signing Requests} {.csr}}
	{{All Files} *}
       } \
      -initialdir certificates \
      -title "Select CSR to sign"]

    if {$csr_fn != "" } {
	
	set attributes [openssl::CSR_GetSubject $csr_fn]
	set attributes [concat $attributes [openssl::CSR_GetType $csr_fn]]
	set attr(exit) [Dialog_ConfirmAttributes .popup {Do you want to sign this request ?} $attributes]
    }
    
    if {$csr_fn != "" && $attr(exit) == "ok"} {
	array set attr [Dialog_AskAttributes .popup {Sign Client Certificate Request} {
	    *password {CA Key Password} {} "!" }]
    }
    
    if {$csr_fn != "" && $attr(exit) == "ok"} {
	
	# key filename = csr filename, but in stead .key extension.
	regsub {\.csr$} $csr_fn {} attr(fn)
	
	update
	
	# sign client request
	openssl::do client_sign signclient attr
	
	#set f [open "config.cfg" w]
	#puts $f [subst -nocommands -nobackslashes $config_file(signclient)]
	#close $f
	##catch {eval exec [subst $cmd(client_sign)]}
	#global env    
	#set env(password) $attr(*password)
	#openssl [subst $cmd(client_sign)]
	#catch {file delete "config.cfg"}
    } 

    # reload certificate info
    GetCertificates .main ca.db.index
}

proc cmd::RevokeCert {} {
    
    debug::msg "cmd::RevokeCert"
    
    # now in openssl::
    #variable cmd    
    #global config_file
    
    # request attributes
    
	
    set csr_fn [tk_getOpenFile -defaultextension .crt \
      -filetypes {
	{{Certificates} {.crt}}
	{{All Files} *}
       } \
      -initialdir certificates \
      -title "Select certificate to revoke"]
    
    if {$csr_fn != "" } {

	set attributes [openssl::CRT_GetSubject $csr_fn]
	set attr(exit) [Dialog_ConfirmAttributes .popup {Do you want to revoke this certificate ?} $attributes]
    }
    
    if {$csr_fn != "" && $attr(exit) == "ok"} {
	array set attr [Dialog_AskAttributes .popup {Revoke Certificate} {
	    *password {CA Key Password}  {}  "!" }]
    }
    
    if {$csr_fn != "" && $attr(exit) == "ok"} {
	
	# key filename = csr filename, but in stead .key extension.
	regsub {\.crt$} $csr_fn {} attr(fn)
	
	update
	
	# revoke cert
	openssl::do srv_revoke signserver attr
	
	#set f [open "config.cfg" w]
	#puts $f [subst -nocommands -nobackslashes $config_file(signserver)]
	#close $f
	##after 1000
	##catch {eval exec [subst $cmd(srv_revoke)]}
	#global env    
	#set env(password) $attr(*password)
	#openssl [subst $cmd(srv_revoke)]
	#catch {file delete "config.cfg"}
	#if {[file exists "ca.db.index.new"]} {
	#    file rename -force "ca.db.index.new" "ca.db.index"
	#}

	# reload certificate info
	GetCertificates .main ca.db.index

    } 

}

proc cmd::RevokeCertByIndex {certs} {
    
    debug::msg "cmd::RevokeCertByIndex $certs"
    

    #now in openssl::
    #variable cmd
    #global config_file
    #set f [open "config.cfg" w]
    #puts $f [subst -nocommands -nobackslashes $config_file(signserver)]
    #close $f

    # request attributes
    
    foreach cert $certs {
	
	set crt_fn "ca.db.certs/$cert.pem"

	set attributes [openssl::CRT_GetSubject $crt_fn]
	set attr(exit) [Dialog_ConfirmAttributes .popup {Do you want to revoke this certificate ?} $attributes]
    
	if {$attr(exit) != "ok"} {
	    break
	}
	
	array set attr [Dialog_AskAttributes .popup {Revoke Certificate} {
	    *password {CA Key Password} {}  "!" }]

	if {$attr(exit) != "ok"} {
	    break
	}
		
	# key filename = csr filename, but in stead .key extension.
	regsub {\.crt$} $crt_fn {} attr(fn)
	
	# revoke cert
	openssl::do cert_revoke signserver attr
	
	#now in openssl::
	#global env    
	#set env(password) $attr(*password)
	##catch {eval exec [subst $cmd(cert_revoke)]}
	#openssl [subst $cmd(cert_revoke)]
	#if {[file exists "ca.db.index.new"]} {
	#    file rename -force "ca.db.index.new" "ca.db.index"
	#}


    } 

    #now in openssl::
    #catch {file delete "config.cfg"}

    # reload certificate info
    GetCertificates .main ca.db.index

}

proc cmd::ViewByIndex {certs} {
    
    debug::msg "cmd::ViewByIndex $certs"
    
    

    # now in openssl::
    #variable cmd
    #global config_file
    #set f [open "config.cfg" w]
    #puts $f [subst -nocommands -nobackslashes $config_file(signserver)]
    #close $f

    # request attributes
    
    foreach cert $certs {
	
	set crt_fn "ca.db.certs/$cert.pem"

	set attributes [openssl::CRT_GetSubject $crt_fn]
	set attr(exit) [Dialog_ConfirmAttributes .popup {Certificate Details} $attributes]

	regsub {\.crt$} $crt_fn {} attr(fn)
	
	openssl::do cert_view signserver attr

	# now in openssl::
	#openssl [subst $cmd(cert_view)]

    } 

    #catch {file delete "config.cfg"}

}

proc cmd::ExportPKCS12 {} {
    
    debug::msg "cmd::ExportPKCS12"
    
    #now in openssl
    #variable cmd    
    #global config_file
    
    # request attributes
    
	
    set attr(csr_fn) [tk_getOpenFile -defaultextension .crt \
      -filetypes {
	{{Certificates} {.crt}}
	{{All Files} *}
       } \
      -initialdir certificates \
      -title "Select certificate to export"]

    # get username & caname defaults
    array set subject [openssl::CRT_GetSubject "ca.crt"]
    set ca_cn $subject(CN)
    array set subject [openssl::CRT_GetSubject $attr(csr_fn)]
    set user_cn $subject(CN)
    
    # request values
    if {$attr(csr_fn) != ""} {
	array set attr [Dialog_AskAttributes .popup {Export Certificate to PKCS12 format} "
	    username {Frienly Username} \"$user_cn\" \"!\"
	    caname {Friendly CAName} \"$ca_cn\" \"!\"
	    *password {PKCS12 Export Password} {} \"!\"
	    *again {Repeat Password} {} \"!\"  " ]
	}

	
    if {$attr(csr_fn) != "" && $attr(exit) == "ok"} {
	
	# key filename = csr filename, but in stead .key extension.
	regsub {\.crt$} $attr(csr_fn) {} attr(fn)
	
	openssl::do export_pkcs12 "" attr
	
	#global env    
	#set env(password) $attr(*password)
	##catch {eval exec [subst $cmd(export_pkcs12)]}
	#openssl [subst $cmd(export_pkcs12)]

    } 

}

proc cmd::GenerateCRL {} {
    
    debug::msg "cmd::GenerateCRL"
    
    #now in openssl
    #variable cmd
    #global config_file
    
    # request attributes
    
    array set attr [Dialog_AskAttributes .popup {Generate Certificate Revocation List} {
	*password {CA Password} {} "!" }]
	
    
    if {$attr(exit) == "ok"} {

	# get CA common name
	array set subject [openssl::CRT_GetSubject "ca.crt"]
	set crl_fn [clock format [clock seconds] -format "%Y-%m-%d"]
	set crl_fn "$subject(CN)-$crl_fn"

	set crl_fn [tk_getSaveFile -defaultextension .crl \
	  -filetypes {
	    {{Certificate Revocation Lists} {.crl}}
	    {{All Files} *}
	} \
	  -initialdir certificates \
	  -initialfile $crl_fn.crl \
	  -title "Enter file name to save CRL"]
    }

    if {$attr(exit) == "ok" && $crl_fn != ""} {
	
	# crl filename = csr filename, but in stead .crl extension.
	regsub {\.crl$} $crl_fn {} attr(fn)
	
	update
	openssl::do gencrl signserver attr
	
	#now in openssl
	#set f [open "config.cfg" w]
	#puts $f [subst -nocommands -nobackslashes $config_file(signserver)]
	#close $f
	##catch {eval exec [subst $cmd(gencrl)]}
	#global env    
	#set env(password) $attr(*password)
	#openssl [subst $cmd(gencrl)]
	#catch {file delete "config.cfg"}

    } 

}



proc cmd::Help {} {
    tk_messageBox -title "Help" -icon info -type ok -message "Help is not yet implemented"
}
proc cmd::About {} {
    tk_messageBox -title "About Simple CA" -icon info -type ok \
      -message "Simple CA,
    
A really really simple CA utility.


Feedback to : joris.ballet@advalvas.be
"

}

proc cmd::HelpReadme {} {
    eval exec [auto_execok start] [list "readme.html"] &
}


MakeMenu {} menu $MenuCommands


if {[lindex $argv 0] == "-debug"} {
    set debug::level 1
}

wm title . "SimpleCA"
. configure -menu .menu
if { [string equal $tcl_platform(platform) windows] } {
    .menu add cascade -label System -menu .menu.system
    menu .menu.system -tearoff 0


    if {[lindex $argv 0] == "-debug"} {
	# Add the 'Show Console' item to the system menu
	::consoleAux::setup
	.menu.system add checkbutton \
	  -label {Show Console} \
	  -variable ::consoleAux::mapped \
	  -command ::consoleAux::toggle
    }
    
    # Add the 'Show Log' item to the system menu
    .menu.system add checkbutton \
      -label {Show Message Log} \
      -variable ::Log::mapped(.log) \
      -command "::Log::WindowToggle .log"
    
  }

#LogWindow::Create .log
#interp alias {} log {} ::LogWindow::LogMessage .log

#if {[info exists log_file]} {
#    close $log_file
#}

#set log_file [open "ca.log" "a"]
#proc log {msg {option ""}} {
#    global log_file
#    ::LogWindow::LogMessage .log $msg $option
#    puts $log_file $msg
#    flush $log_file
#}

#wm protocol . WM_DELETE_WINDOW "close $log_file; destroy ."

Log::CreateWindow .log
Log::ToWindow .log
Log::ToFile "ca.log"
interp alias {} log {} ::Log::LogMessage
wm protocol . WM_DELETE_WINDOW "Log::Cleanup; destroy ."

    
debug::msg "startup : $argv0 $argv"

CertificateListBox .main
pack .main -expand 1 -fill both
update

# if not yet set up - start set up
while {![file exists ca.key]} {
    
    cmd::SetupRootCA

    # if still not yet set - bail out
    if {![file exists ca.key]} {

	set answer [tk_messageBox -icon error -type retrycancel -message "Unknown Error setting up Root CA - did you install openssl ?"]
	if {$answer == "cancel"} {
		exit 1
	}
    }
}



GetCertificates .main ca.db.index


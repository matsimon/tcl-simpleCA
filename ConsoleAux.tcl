# The ''consoleAux'' namespace holds variables and procedures
# that help manage the system console on Windows
    
namespace eval consoleAux {
    
    namespace export setup;		# Initialization
    
    namespace export toggle;	# Command to map/unmap the
    # console on demand
    
    variable mapped;		# Flag == 1 iff the console
    # is currently mapped
    
}

#------------------------------------------------------------------
#
# consoleAux::setup --
#
#	    Set up the system console control on Windows.
#
# Parameters:
#       None.
#
# Results:
#       None.
#
# Side effects:
#       Bindings are established so that the variable,
#       '::consoleAux::mapped' is set to reflect the state
#       of the console.
#
# Notes:
#       Depends on undocumented internal API's of Tk and
#       therefore may not work on future releases.
#
#------------------------------------------------------------------

proc consoleAux::setup {} {
    
    # Make the console have a sensible title
    
    console title "Console: [tk appname]"
    
    console eval {
	
	# Determine whether the console has started in the
	# mapped state.
	
	if { [winfo ismapped .console] } {
	    consoleinterp eval {
		set ::consoleAux::mapped 1
	    }
	} else {
	    consoleinterp eval {
		set ::consoleAux::mapped 0
	    }
	}
	
	# Establish bindings to reflect the state of the
	# console in the 'mapped' variable.
	
	bind .console <Map> {
	    consoleinterp eval {
		set ::consoleAux::mapped 1
	    }
	}
	bind .console <Unmap> {
	    consoleinterp eval {
		set ::consoleAux::mapped 0
	    }
	}
    }

    return
}

#------------------------------------------------------------------
#
# consoleAux::toggle --
#
#       Change the 'mapped' state of the console in response
#       to a checkbutton.
#
# Parameters:
#       None.
#
# Results:
#       None.
#
# Side effects:
#       If the console is marked 'mapped', shows and raises it.
#       Otherwise, hides it.
#
#------------------------------------------------------------------

proc consoleAux::toggle {} {
    variable mapped
    if {$mapped} {
	console show
	console eval { raise . }
    } else {
	console hide
    }
    return
}

# Sample application that shows the use of the console in the
# system menu.

# First, make sure there is a system menu.

#menu .menubar
#. configure -menu .menubar

#.menubar add cascade -label File -menu .menubar.file -underline 0

#menu .menubar.file
#.menubar.file add command -label Exit -underline 1 -command exit

#if { [string equal $tcl_platform(platform) windows] } {
#    .menubar add cascade -label System -menu .menubar.system
#    
#    menu .menubar.system -tearoff 0
#    
#    # Add the 'Show Console' item to the system menu
#    
#    ::consoleAux::setup
#    .menubar.system add checkbutton \
#      -label {Show Console} \
#      -variable ::consoleAux::mapped \
#      -command ::consoleAux::toggle
#    
#  }
#  
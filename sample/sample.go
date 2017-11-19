// sample.go
// Sample code for package "github.com/bunji2/cvssv3"

package main

import (
	"fmt"
	"os"
	"github.com/bunji2/cvssv3"
)

func usage() {
	fmt.Printf(`CVSSv3 calcurator by Bunji2

Usage: %s cvss_string

  The format of cvss_string follows:
  cvss_string ::= CVSS:3.0/base
                | CVSS:3.0/base/temp
                | CVSS:3.0/base/temp/env
  base ::= AV:[N,A,L,P]/AC:[L,H]]/PR:[N,L,P]]/UI:[N,R]/S:[U,C]/C:[H,L,N]/I:[H,L,N]/A:[H,L,N]
  temp ::= E:[X,U,P,F,H]/RL:[X,O,T,W,U]/RC:[X,U,R,C]
  env ::= CR:[X,H,M,L]/IR:([X,H,M,L]/AR:[X,H,M,L]/MAV:[X,N,A,L,P]/MAC:[X,L,H]/MPR:[X,N,L,H]/MUI:[X,N,R]/MS:[X,U,C]/MC:[X,H,L,N]/MI:[X,H,L,N]/MA:[X,H,L,N]

Example:

  %% cvssv3 CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L
  CVSS String: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L/E:X/RL:X/RC:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X
  Base Score:  8.6
  Temporal Score:  8.6
  Environmental Score:  8.6

Specification of CVSSv3:

  https://www.first.org/cvss/specification-document
`, os.Args[0])
}

func main () {
	if len(os.Args) < 2 {
		usage()
		return
	}
	v, err := cvssv3.ParseVector(os.Args[1])
        //"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
	if err != nil {
        panic(err) // if string is invalid.
	}
	fmt.Printf("CVSS String: %s \n", v.String())
	fmt.Printf("Base Score: %4.1f \n", v.BaseScore())
	fmt.Printf("Temporal Score: %4.1f \n", v.TemporalScore())
	fmt.Printf("Environmental Score: %4.1f \n", v.EnvironmentalScore())
	

}

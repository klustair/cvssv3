# bunji2/cvssv3

A Common Vulnerability Scoring System Version 3.0 (CVSSv3) implementation for golang.

Inspired by "go-cvss" ( https://github.com/umisama/go-cvss ), but implementated in different way.

## Installation

```
go get github.com/bunji2/cvssv3
``` 

## Usage

```go
import (
    "fmt"
    "github.com/bunji2/cvssv3"
)

func sample() {
    v, err := cvssv3.ParseVector(
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    if err != nil {
        panic(err)
    }
    fmt.Printf("CVSS String: %s \n", v.String())
    fmt.Printf("Base Score: %4.1f \n", v.BaseScore())
    fmt.Printf("Temporal Score: %4.1f \n", v.TemporalScore())
    fmt.Printf("Environmental Score: %4.1f \n", v.EnvironmentalScore())
}
```
## Document

 * [godoc.org](https://godoc.org/github.com/bunji2/cvssv3)

## Reference

 * [Common Vulnerability Scoring System v3.0: Specification Document](https://www.first.org/cvss/specification-document)

## License

under the MIT License

by Bunji2

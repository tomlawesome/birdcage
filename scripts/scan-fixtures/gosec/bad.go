// Planted defect for the gosec self-test (#199). Its own module, so ./... of
// the main module never sees it. Expected: G401 (md5), the only rule the
// self-test asserts; gosec does not raise G204 for the exec.Command call
// here. Contains no credential.
package main

import (
	"crypto/md5"
	"fmt"
	"os/exec"
)

func main() {
	sum := md5.Sum([]byte("planted"))
	fmt.Printf("%x\n", sum)
	name := "echo"
	_ = exec.Command(name, "planted").Run()
}

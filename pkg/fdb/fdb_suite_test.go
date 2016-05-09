package fdb_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"
)

func TestFdb(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Forwarding database Suite")
}

package fdb_test

import (
	"fmt"
	"net"
	"sync"

	"github.com/coreos/flannel/pkg/fdb"
	"github.com/coreos/flannel/pkg/ip"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func mustParseIP4Net(cidr string) ip.IP4Net {
	_, val, err := net.ParseCIDR(cidr)
	Expect(err).NotTo(HaveOccurred())
	return ip.FromIPNet(val)
}

func mustParseUDPAddr(hostPort string) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp", hostPort)
	Expect(err).NotTo(HaveOccurred())
	return addr
}

var _ = Describe("Forwarding database", func() {
	var (
		db fdb.UDPForwardingDB

		underlayEndpoint1, underlayEndpoint2, underlayEndpoint3 *net.UDPAddr
	)

	BeforeEach(func() {
		db = fdb.NewUDPForwardingDB()
	})

	Describe("finding an underlay endpoint", func() {
		BeforeEach(func() {
			overlaySubnet1 := mustParseIP4Net("10.10.1.0/24")
			underlayEndpoint1 = mustParseUDPAddr("192.168.1.1:7654")

			overlaySubnet2 := mustParseIP4Net("10.10.2.0/24")
			underlayEndpoint2 = mustParseUDPAddr("192.168.2.2:7654")

			overlaySubnet3 := mustParseIP4Net("10.10.3.0/24")
			underlayEndpoint3 = mustParseUDPAddr("192.168.3.3:7654")

			Expect(db.Add(overlaySubnet1, underlayEndpoint1)).To(Succeed())
			Expect(db.Add(overlaySubnet2, underlayEndpoint2)).To(Succeed())
			Expect(db.Add(overlaySubnet3, underlayEndpoint3)).To(Succeed())

		})
		It("returns the correct endpoint", func() {
			foundEP, err := db.FindUnderlayEndpoint(ip.MustParseIP4("10.10.2.25"))
			Expect(err).NotTo(HaveOccurred())
			Expect(foundEP).To(BeIdenticalTo(underlayEndpoint2))
		})

		Context("when there is no forwarding entry to the subnet", func() {
			It("returns a meaningful error", func() {
				Expect(db.Remove(mustParseIP4Net("10.10.2.0/24"))).To(Succeed())

				_, err := db.FindUnderlayEndpoint(ip.MustParseIP4("10.10.2.25"))
				Expect(err).To(BeIdenticalTo(fdb.ErrorMissingEntry))
			})
		})
	})

	Describe("concurrent access (run this test with the race detector)", func() {
		It("remains consistent", func() {
			var adder sync.WaitGroup

			maxI := 10
			maxJ := 10
			const toPreserve = 7
			toRemove := make(chan ip.IP4Net, maxI*maxJ)
			for i := 0; i < maxI; i++ {
				for j := 0; j < maxJ; j++ {
					overlaySubnet := mustParseIP4Net(fmt.Sprintf("10.%d.%d.0/24", i, j))
					underlayEndpoint := mustParseUDPAddr(fmt.Sprintf("192.168.%d.%d:7654", i, j))

					j := j
					adder.Add(1)
					go func() {
						defer GinkgoRecover()
						Expect(db.Add(overlaySubnet, underlayEndpoint)).To(Succeed())
						if j != toPreserve {
							toRemove <- overlaySubnet
						}
						adder.Done()
					}()
				}
			}

			var remover sync.WaitGroup
			remover.Add(1)
			go func() {
				defer GinkgoRecover()
				for s := range toRemove {
					Expect(db.Remove(s)).To(Succeed())
				}
				remover.Done()
			}()
			adder.Wait()
			close(toRemove)
			remover.Wait()

			for i := 0; i < maxI; i++ {
				foundEP, err := db.FindUnderlayEndpoint(ip.MustParseIP4(fmt.Sprintf(
					"10.%d.%d.42", i, toPreserve)))
				Expect(err).NotTo(HaveOccurred())
				Expect(foundEP).To(Equal(mustParseUDPAddr(fmt.Sprintf(
					"192.168.%d.%d:7654", i, toPreserve))))
			}
		})
	})
})

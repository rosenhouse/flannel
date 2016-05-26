package policy_test

import (
	"net"
	"policy-server/models"

	"github.com/coreos/flannel/pkg/policy"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pivotal-golang/lager/lagertest"
)

var _ = Describe("Dynamic policy", func() {
	var pol policy.DynamicPolicy

	BeforeEach(func() {
		tagLength := 4
		logger := lagertest.NewTestLogger("test")
		tunnelEndpointIP := net.ParseIP("1.1.1.0")
		controlTag := []byte("MGMT")
		pol = policy.NewDynamicPolicy(logger, tagLength, tunnelEndpointIP, controlTag)
	})

	It("reports the configured tag length", func() {
		Expect(pol.TagLength()).To(Equal(4))
	})

	It("enforces a default deny rule", func() {
		isAllowed, err := pol.IsAllowed([]byte("fail"), net.ParseIP("2.2.2.2"))
		Expect(err).NotTo(HaveOccurred())
		Expect(isAllowed).To(BeFalse())
	})

	It("refuses to return a tag for unregistered endpoints", func() {
		_, err := pol.GetSourceTag(net.ParseIP("1.1.1.1"))
		Expect(err).To(Equal(policy.ErrorUnknownLocalSource))
	})

	Context("ICMP traffic support", func() {
		Context("when the source ip is the tunnel endpoint itself", func() {
			It("applies the control-plane tag", func() {
				tag, err := pol.GetSourceTag(net.ParseIP("1.1.1.0"))
				Expect(err).NotTo(HaveOccurred())
				Expect(tag).To(Equal([]byte("MGMT")))
			})
		})

		Context("when the destination ip is the tunnel endpoint itself", func() {
			It("allows the packet", func() {
				isAllowed, err := pol.IsAllowed([]byte("????"), net.ParseIP("1.1.1.0"))
				Expect(err).NotTo(HaveOccurred())
				Expect(isAllowed).To(BeTrue())
			})
		})

		Context("when the incoming packet has the control-plane tag", func() {
			It("allows the packet", func() {
				isAllowed, err := pol.IsAllowed([]byte("MGMT"), net.ParseIP("4.4.4.4"))
				Expect(err).NotTo(HaveOccurred())
				Expect(isAllowed).To(BeTrue())
			})
		})
	})

	Context("when an endpoint has been registered", func() {
		BeforeEach(func() {
			err := pol.Register(policy.Endpoint{
				ContainerID: "container1",
				GroupID:     "group1",
				OverlayIP:   net.ParseIP("1.1.1.1"),
			})
			Expect(err).NotTo(HaveOccurred())

			err = pol.Register(policy.Endpoint{
				ContainerID: "container2",
				GroupID:     "group2",
				OverlayIP:   net.ParseIP("2.2.2.2"),
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It("reports the endpoint group", func() {
			groups, err := pol.GetGroups()
			Expect(err).NotTo(HaveOccurred())
			Expect(groups).To(ConsistOf([]string{"group1", "group2"}))
		})

		It("still enforces the default deny rule", func() {
			isAllowed, err := pol.IsAllowed([]byte("fail"), net.ParseIP("2.2.2.2"))
			Expect(err).NotTo(HaveOccurred())
			Expect(isAllowed).To(BeFalse())
		})

		It("supports deregistering the endpoint via just the container ID", func() {
			err := pol.Deregister(policy.Endpoint{
				ContainerID: "container1",
			})
			Expect(err).NotTo(HaveOccurred())
			groups, err := pol.GetGroups()
			Expect(err).NotTo(HaveOccurred())
			Expect(groups).To(ConsistOf([]string{"group2"}))
		})

		It("refuses to return a tag for endpoints without a tag", func() {
			_, err := pol.GetSourceTag(net.ParseIP("1.1.1.1"))
			Expect(err).To(MatchError(policy.ErrorUnknownLocalSource))
		})

		Context("when a policy has been set for the group", func() {
			BeforeEach(func() {
				err := pol.SetWhitelists([]models.IngressWhitelist{
					{
						Destination: models.TaggedGroup{
							ID:  "group1",
							Tag: models.PT("atag"),
						},
						AllowedSources: []models.TaggedGroup{
							models.TaggedGroup{
								ID:  "group3",
								Tag: models.PT("ctag"),
							},
						},
					},
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It("returns the tag when provided as a destination", func() {
				tag, err := pol.GetSourceTag(net.ParseIP("1.1.1.1"))
				Expect(err).NotTo(HaveOccurred())
				Expect(tag).To(Equal([]byte("atag")))
			})

			It("still enforces the default deny rule", func() {
				isAllowed, err := pol.IsAllowed([]byte("fail"), net.ParseIP("1.1.1.1"))
				Expect(err).NotTo(HaveOccurred())
				Expect(isAllowed).To(BeFalse())
			})

			It("allows traffic from the whitelisted group", func() {
				isAllowed, err := pol.IsAllowed([]byte("ctag"), net.ParseIP("1.1.1.1"))
				Expect(err).NotTo(HaveOccurred())
				Expect(isAllowed).To(BeTrue())
			})

			It("scopes the allowed traffic only to the specified destination", func() {
				isAllowed, err := pol.IsAllowed([]byte("ctag"), net.ParseIP("2.2.2.2"))
				Expect(err).NotTo(HaveOccurred())
				Expect(isAllowed).To(BeFalse())
			})
		})
	})
})

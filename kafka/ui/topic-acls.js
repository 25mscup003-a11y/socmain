// Kafbat v1.5.0's compiled Topic module already imports ClusterContext (Hi),
// React (Me), the JSX runtime (j), and the themed status panel (pc).
// Mount the original query component only when the broker supports ACLs.
ov = () => {
  const { hasAclViewConfigured } = Me.useContext(Hi);
  return hasAclViewConfigured
    ? j.jsx(ajnatTopicAclsEnabled, {})
    : j.jsxs(pc, {
        role: "status",
        children: [
          j.jsx("h3", { children: "ACLs are not enabled for this cluster" }),
          j.jsx("p", {
            children: "This Kafka broker has no ACL authorizer configured. There are no topic access-control rules to display.",
          }),
        ],
      });
},
ajnatTopicAclsEnabled = __ORIGINAL_TOPIC_ACLS__

package cluster

type OperationPolicy struct {
	Operation          string `json:"operation"`
	FanOutRead         bool   `json:"fan_out_read"`
	TargetedRemote     bool   `json:"targeted_remote"`
	PropagatableLater  bool   `json:"propagatable_later"`
	AuthoritativeOwner bool   `json:"authoritative_owner"`
	NodeLocalOnly      bool   `json:"node_local_only"`
}

var Policies = []OperationPolicy{
	{Operation: "cluster.health", FanOutRead: true, TargetedRemote: true},
	{Operation: "monitor.status", FanOutRead: true, TargetedRemote: true, AuthoritativeOwner: true},
	{Operation: "monitor.definition", TargetedRemote: true, PropagatableLater: true, AuthoritativeOwner: true},
	{Operation: "request.definition", TargetedRemote: true, PropagatableLater: true, AuthoritativeOwner: true},
	{Operation: "environment.definition", TargetedRemote: true, PropagatableLater: true, AuthoritativeOwner: true},
	{Operation: "schedule.definition", TargetedRemote: true, PropagatableLater: true, AuthoritativeOwner: true},
	{Operation: "execution.run", TargetedRemote: true, AuthoritativeOwner: true},
	{Operation: "results.history", FanOutRead: true, TargetedRemote: true, AuthoritativeOwner: true},
	{Operation: "secrets", AuthoritativeOwner: true, NodeLocalOnly: true},
	{Operation: "scheduler.runtime", AuthoritativeOwner: true, NodeLocalOnly: true},
	{Operation: "browser.runtime", NodeLocalOnly: true},
}

func PolicyFor(op string) (OperationPolicy, bool) {
	for _, p := range Policies {
		if p.Operation == op {
			return p, true
		}
	}
	return OperationPolicy{}, false
}

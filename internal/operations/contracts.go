// Package operations declares Webfleet's canonical functional operation surface.
package operations
import("github.com/gantry-tools/gantry-core/contracttest";"github.com/gantry-tools/gantry-core/operation")
var Contracts=[]operation.Contract{
	contract("webfleet.sites.list",operation.Read,"GET","/api/sites","sites","list",""),
	contract("webfleet.sites.create",operation.Mutation,"POST","/api/sites","sites","create","webfleet.sites.created"),
	contract("webfleet.sites.archive",operation.Destructive,"POST","/api/sites/{id}/archive","sites","archive","webfleet.sites.archived"),
}
func contract(id string,kind operation.Kind,method,path,resource,verb,event string)operation.Contract{audit:=operation.Audit{};scope:="sites.read";if kind!=operation.Read{audit=operation.Audit{Required:true,Event:event};scope="sites.write"};return operation.Contract{SchemaVersion:operation.SchemaVersion,ID:id,Kind:kind,Route:operation.Route{Method:method,Path:path},CLI:&operation.CLI{Resource:resource,Verb:verb},Authorization:operation.Authorization{Boundary:operation.Session,TokenScopes:[]string{scope}},Audit:audit,Idempotency:operation.Idempotency{RetrySafe:kind==operation.Read},Automation:operation.Automatable}}
func AdoptionManifest()contracttest.Manifest{routes:=make([]operation.Route,len(Contracts));ids:=make([]string,len(Contracts));for i,c:=range Contracts{routes[i],ids[i]=c.Route,c.ID};return contracttest.Manifest{SchemaVersion:1,Project:"webfleet",Operations:Contracts,ObservedRoutes:routes,WebsiteOperations:ids}}

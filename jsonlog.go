/*

Example config:
jsonlog {
#	pgdb postgresql://crate@192.168.0.193:5432/doc
influxdb http://192.168.0.193:8086/ test dns_data base64keyhere==
}

*/
package jsonlog

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"

	"github.com/influxdata/influxdb-client-go/v2"
	"github.com/jackc/pgx/v4/pgxpool"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

const (
	coreDNSPackageName string = `jsonlog`
)

var log = clog.NewWithPlugin(coreDNSPackageName)

func init() {
	caddy.RegisterPlugin(coreDNSPackageName, caddy.Plugin{
		ServerType: `dns`,
		Action:     setup,
	})
}

// JsonLog is the  plugin.
type JsonLog struct {
	SQL         *pgxpool.Pool
	IFDB        influxdb2.Client
	IFDB_org    string
	IFDB_bucket string
	Next        plugin.Handler
}

func New() *JsonLog {
	return &JsonLog{}
}

func setup(c *caddy.Controller) error {

	jsonlog := New()

	for c.Next() {
		for c.NextBlock() {
			var arg, val string
			arg = c.Val()
			c.NextArg()
			val = c.Val()
			c.NextArg()
			switch arg {
			case `pgdb`:
				{
					conn, err := pgxpool.Connect(context.Background(), val)
					if err != nil {
						panic("Unable to connect to database")
					}
					jsonlog.SQL = conn
				}
			case `influxdb`:
				{
					org := c.Val()
					c.NextArg()
					bucket := c.Val()
					c.NextArg()
					token := c.Val()
					c.NextArg()
					jsonlog.IFDB = influxdb2.NewClient(val, token) //tbd keep handle around to later close it
					jsonlog.IFDB_org = org
					jsonlog.IFDB_bucket = bucket
				}
			}
		}
	}

	if jsonlog.SQL == nil && jsonlog.IFDB == nil {
		log.Fatal("no   connection")
		return nil
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		jsonlog.Next = next
		return jsonlog
	})

	return nil
}

func (plugin JsonLog) String() string {
	return coreDNSPackageName
}

func (plugin JsonLog) Name() string {
	return coreDNSPackageName
}

type EventData struct {
	Q           []dns.Question
	A           []dns.RR
	FirstName   string
	FirstAnswer string
	Local       string
	Remote      string
	Timestamp   time.Time
}

type DNSEvent struct {
	dns.ResponseWriter
	data EventData
}

func (i *DNSEvent) Write(b []byte) (int, error) {
	return i.ResponseWriter.Write(b)
}

func (i *DNSEvent) WriteMsg(m *dns.Msg) error {
	i.data.Q = m.Question
	i.data.A = m.Answer
	return i.ResponseWriter.WriteMsg(m)
}

func (i *DNSEvent) String() string {
	x, _ := json.Marshal(i.data)
	return string(x)
}

func (plugin JsonLog) ServeDNS(ctx context.Context, rw dns.ResponseWriter, r *dns.Msg) (c int, err error) {
	local := rw.LocalAddr()
	remote := rw.RemoteAddr()

	event := &DNSEvent{
		ResponseWriter: rw,
	}
	event.data.Timestamp = time.Now()
	event.data.Local = local.String()
	event.data.Remote = remote.String()

	c, err = plugin.Next.ServeDNS(ctx, event, r)

	if len(event.data.Q) >= 1 {
		//set FirstName
		event.data.FirstName = event.data.Q[0].Name
	}

	if len(event.data.A) >= 1 {
		//set FirstName
		event.data.FirstName = event.data.A[0].Header().Name

		//Answers can be A, AAAA, CNAME, etc. To simplify things get the string form
		//and use the separator. FirstName/FirstString will make it easy to classify results downstream

		//TBD ... maybe pick the ip address as the first answer?
		answerString := event.data.A[0].String()
		parts := strings.Split(answerString, "\t")
		event.data.FirstAnswer = parts[len(parts)-1]
	}

	plugin.PushEvent(event)

	return
}

func (plugin JsonLog) PushEvent(event *DNSEvent) {

	if plugin.SQL != nil {
		_, err := plugin.SQL.Exec(context.Background(), "INSERT INTO dns(data) VALUES(?)", event.String())
		if err != nil {
			fmt.Println("exec tx")
			log.Fatal(err)
		}
	} else if plugin.IFDB != nil {
		writeAPI := plugin.IFDB.WriteAPI(plugin.IFDB_org, plugin.IFDB_bucket)

		p := influxdb2.NewPointWithMeasurement("dns").
			AddField("FirstName", event.data.FirstName).
			AddField("FirstAnswer", event.data.FirstAnswer).
			AddField("Remote", event.data.Remote).
			AddField("Local", event.data.Local)

		writeAPI.WritePoint(p)
		writeAPI.Flush()
	}

}

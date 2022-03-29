/*

Example config:
jsonlog {
enable_superapi
influxdb http://192.168.0.193:8086/ test dns_data base64keyhere==
#	pgdb postgresql://crate@192.168.0.193:5432/doc
}

*/
package jsonlog

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"

	"github.com/influxdata/influxdb-client-go/v2"
	"github.com/jackc/pgx/v4/pgxpool"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/response"
)

const (
	coreDNSPackageName      string = `jsonlog`
	CLIENT_MEMORY_LOG_COUNT int    = 1024
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
	SQL              *pgxpool.Pool
	config           SPRLogConfig
	IFDB             influxdb2.Client
	IFDB_org         string
	IFDB_bucket      string
	Next             plugin.Handler
	superapi_enabled bool
}

func New() *JsonLog {
	return &JsonLog{}
}

func setup(c *caddy.Controller) error {

	superapi_enabled := false

	jsonlog := New()

	for c.Next() {
		for c.NextBlock() {
			var arg, val string
			arg = c.Val()
			c.NextArg()

			if arg == `enable_superapi` {
				superapi_enabled = true
				arg = c.Val()
				c.NextArg()
			}

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

	jsonlog.superapi_enabled = superapi_enabled

	if jsonlog.SQL == nil && jsonlog.IFDB == nil && !superapi_enabled {
		log.Fatal("no   connection")
		return nil
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		jsonlog.Next = next
		return jsonlog
	})

	if jsonlog.superapi_enabled {
		go func() {
			jsonlog.loadSPRConfig()
			jsonlog.runAPI()
		}()
	}

	return nil
}

func (plugin *JsonLog) String() string {
	return coreDNSPackageName
}

func (plugin *JsonLog) Name() string {
	return coreDNSPackageName
}

type EventData struct {
	Q           []dns.Question
	A           []dns.RR
	Type        string
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

	tpe, _ := response.Typify(m, time.Now().UTC())

	i.data.Type = tpe.String()
	i.data.Q = m.Question
	i.data.A = m.Answer
	return i.ResponseWriter.WriteMsg(m)
}

func (i *DNSEvent) String() string {
	x, _ := json.Marshal(i.data)
	return string(x)
}

func (plugin *JsonLog) ServeDNS(ctx context.Context, rw dns.ResponseWriter, r *dns.Msg) (c int, err error) {
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

	return c, err
}

var EventMemoryMtx sync.Mutex
var EventMemoryIdx = make(map[string]int)
var EventMemory = make(map[string]*[CLIENT_MEMORY_LOG_COUNT]EventData)

func (plugin *JsonLog) PushEvent(event *DNSEvent) {
	client := strings.Split(event.data.Remote, ":")[0]

	for _, entry := range plugin.config.HostPrivacyIPList {
		if entry == client {
			// no logs for entries in the privacy list
			return
		}
	}
	for _, entry := range plugin.config.DomainIgnoreList {
		if entry == event.data.FirstName {
			// ignore domain
			return
		}
	}

	if plugin.superapi_enabled {
		EventMemoryMtx.Lock()
		idx := EventMemoryIdx[client]
		if idx >= CLIENT_MEMORY_LOG_COUNT {
			idx = 0
		}
		EventMemoryIdx[client] = idx + 1

		val, exists := EventMemory[client]
		if !exists {
			val = &[CLIENT_MEMORY_LOG_COUNT]EventData{}
			//assign pointer once
			EventMemory[client] = val
		}
		val[idx] = event.data
		EventMemoryMtx.Unlock()
	}

	if plugin.SQL != nil {
		_, err := plugin.SQL.Exec(context.Background(), "INSERT INTO dns(data) VALUES(?)", event.String())
		if err != nil {
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

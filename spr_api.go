package jsonlog

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
)

import (
	"github.com/gorilla/mux"
)

var TEST_PREFIX = os.Getenv("TEST_PREFIX")

var UNIX_PLUGIN_LISTENER = TEST_PREFIX + "/state/dns/dns_log_plugin"
var CONFIG_PATH = TEST_PREFIX + "/state/dns/log_rules.json"

type SPRLogConfig struct {
	HostPrivacyIPList []string //list of local IPs to ignore for logs
	DomainIgnoreList  []string //list of local IPs to ignore for logs
	StoreLocalMemory  bool
}

var Configmtx sync.Mutex

func (plugin *JsonLog) loadSPRConfig() {
	Configmtx.Lock()
	defer Configmtx.Unlock()
	data, err := ioutil.ReadFile(CONFIG_PATH)

	if string(data) != "" {
		err = json.Unmarshal(data, &plugin.config)
		if err != nil {
			log.Fatal(err)
		}
	}

	if plugin.config.HostPrivacyIPList == nil {
		plugin.config.HostPrivacyIPList = []string{}
	}

	if plugin.config.DomainIgnoreList == nil {
		plugin.config.DomainIgnoreList = []string{}
	}
}

func (plugin *JsonLog) removeHostIPFromConfig(IP string) {

	plugin.loadSPRConfig()

	index := slices.Index(plugin.config.HostPrivacyIPList, IP)
	if index != -1 {
		plugin.config.HostPrivacyIPList = slices.Delete(plugin.config.HostPrivacyIPList, index, index+1)
		plugin.saveConfig()
	}
}

func (plugin *JsonLog) saveConfig() {
	Configmtx.Lock()
	defer Configmtx.Unlock()

	file, _ := json.MarshalIndent(plugin.config, "", " ")
	err := ioutil.WriteFile(CONFIG_PATH, file, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func (plugin *JsonLog) showConfig(w http.ResponseWriter, r *http.Request) {
	//reload
	plugin.loadSPRConfig()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(plugin.config)
}

func (plugin *JsonLog) hostPrivacyList(w http.ResponseWriter, r *http.Request) {
	//reload
	plugin.loadSPRConfig()

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(plugin.config.HostPrivacyIPList)
		return
	}

	hostPrivacyList := []string{}
	err := json.NewDecoder(r.Body).Decode(&hostPrivacyList)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	//validate every string is a valid IP
	for _, ip := range hostPrivacyList {
		if net.ParseIP(ip) == nil {
			http.Error(w, "Invalid IP: "+ip, 400)
			return
		}
	}

	plugin.config.HostPrivacyIPList = hostPrivacyList

	plugin.saveConfig()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(plugin.config.HostPrivacyIPList)
}

func (plugin *JsonLog) excludeDomain(w http.ResponseWriter, r *http.Request) {
	//reload
	plugin.loadSPRConfig()

	domain := mux.Vars(r)["domain"]

	if domain == "" {
		http.Error(w, "Empty domain string", 400)
		return
	}

	if r.Method == http.MethodDelete {
		for idx, d := range plugin.config.DomainIgnoreList {
			if d == domain {
				plugin.config.DomainIgnoreList = append(plugin.config.DomainIgnoreList[:idx], plugin.config.DomainIgnoreList[idx+1:]...)
				break
			}
		}
	} else {

		for _, d := range plugin.config.DomainIgnoreList {
			if d == domain {
				//already exists
				http.Error(w, "Duplicate domain", 400)
				return
			}
		}

		plugin.config.DomainIgnoreList = append(plugin.config.DomainIgnoreList, domain)
	}

	plugin.saveConfig()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(plugin.config.DomainIgnoreList)
}

func (plugin *JsonLog) listIgnoreDomains(w http.ResponseWriter, r *http.Request) {
	//reload
	plugin.loadSPRConfig()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(plugin.config.DomainIgnoreList)
}

func (plugin *JsonLog) IPQueryHistory(w http.ResponseWriter, r *http.Request) {
	Configmtx.Lock()
	defer Configmtx.Unlock()

	if !plugin.config.StoreLocalMemory {
		http.Error(w, "StoreLocalMemory configuration off", 400)
		return
	}
	ip := mux.Vars(r)["ip"]

	retval := []EventData{}

	EventMemoryMtx.Lock()

	if r.Method == http.MethodDelete {
		EventMemoryIdx[ip] = 0
		EventMemory[ip] = &[CLIENT_MEMORY_LOG_COUNT]EventData{}
		EventMemoryMtx.Unlock()
		return
	}

	val, exists := EventMemory[ip]
	if exists {

		last_idx := EventMemoryIdx[ip]

		//circular buffer. grab from last_idx+1 ... end, and then 0 ... last_idx

		idx := last_idx + 1

		//idx ... end
		for idx < CLIENT_MEMORY_LOG_COUNT {
			entry := val[idx]
			if entry.Q == nil {
				break
			}
			retval = append(retval, entry)
			idx++
		}

		idx = 0
		for idx < last_idx {
			entry := val[idx]
			if entry.Q == nil {
				break
			}
			retval = append(retval, entry)
			idx++
		}
	}

	EventMemoryMtx.Unlock()

	if !exists {
		http.Error(w, "Not found", 404)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(retval)
}

func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/healthy" {
			fmt.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		}
		handler.ServeHTTP(w, r)
	})
}

func (plugin *JsonLog) runAPI() {
	plugin.loadSPRConfig()

	unix_plugin_router := mux.NewRouter().StrictSlash(true)

	unix_plugin_router.HandleFunc("/config", plugin.showConfig).Methods("GET")
	unix_plugin_router.HandleFunc("/host_privacy_list", plugin.hostPrivacyList).Methods("GET", "PUT")
	unix_plugin_router.HandleFunc("/domain_ignore/{domain}", plugin.excludeDomain).Methods("PUT", "DELETE")
	unix_plugin_router.HandleFunc("/domain_ignores", plugin.listIgnoreDomains).Methods("GET")

	unix_plugin_router.HandleFunc("/history/{ip}", plugin.IPQueryHistory).Methods("GET", "DELETE")
	//unix_plugin_router.HandleFunc("/QueryHistory", plugin.QueryHistory).Methods("GET")

	os.Remove(UNIX_PLUGIN_LISTENER)
	unixPluginListener, err := net.Listen("unix", UNIX_PLUGIN_LISTENER)
	if err != nil {
		panic(err)
	}

	pluginServer := http.Server{Handler: logRequest(unix_plugin_router)}

	pluginServer.Serve(unixPluginListener)
}

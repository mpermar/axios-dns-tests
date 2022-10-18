import axios from 'axios'
import dns from 'dns'
import URL from 'url'
import net from 'net'
import stringify from 'json-stringify-safe'
import LRUCache from 'lru-cache'
import util from 'util'
import { init as initLogger } from './logging.js'

const dnsResolve = util.promisify(dns.resolve)
const dnsLookup = util.promisify(dns.lookup)

const config = {
  disabled: process.env.AXIOS_DNS_DISABLE === 'true',
  dnsTtlMs: process.env.AXIOS_DNS_CACHE_TTL_MS || 5000, // when to refresh actively used dns entries (5 sec)
  cacheGraceExpireMultiplier: process.env.AXIOS_DNS_CACHE_EXPIRE_MULTIPLIER || 2, // maximum grace to use entry beyond TTL
  dnsIdleTtlMs: process.env.AXIOS_DNS_CACHE_IDLE_TTL_MS || 1000 * 60 * 60, // when to remove entry entirely if not being used (1 hour)
  backgroundScanMs: process.env.AXIOS_DNS_BACKGROUND_SCAN_MS || 2400, // how frequently to scan for expired TTL and refresh (2.4 sec)
  dnsCacheSize: process.env.AXIOS_DNS_CACHE_SIZE || 100, // maximum number of entries to keep in cache
  // pino logging options
  logging: {
    name: 'axios-cache-dns-resolve',
    // enabled: true,
    level: process.env.AXIOS_DNS_LOG_LEVEL || 'info', // default 'info' others trace, debug, info, warn, error, and fatal
    // timestamp: true,
    prettyPrint: process.env.NODE_ENV === 'DEBUG' || false,
    formatters: {
      level(label/* , number */) {
        return { level: label }
      },
    },
  },
  cache: undefined,
}

const cacheConfig = {
  max: config.dnsCacheSize,
  ttl: (config.dnsTtlMs * config.cacheGraceExpireMultiplier), // grace for refresh
}

const stats = {
  dnsEntries: 0,
  refreshed: 0,
  hits: 0,
  misses: 0,
  idleExpired: 0,
  errors: 0,
  lastError: 0,
  lastErrorTs: 0,
}

let log
let backgroundRefreshId
let cachePruneId

function init() {
  log = initLogger(config.logging)

  if (config.cache) return

  config.cache = new LRUCache(cacheConfig)

  startBackgroundRefresh()
  startPeriodicCachePrune()
  cachePruneId = setInterval(() => config.cache.purgeStale(), config.dnsIdleTtlMs)
}

function startBackgroundRefresh() {
  if (backgroundRefreshId) clearInterval(backgroundRefreshId)
  backgroundRefreshId = setInterval(backgroundRefresh, config.backgroundScanMs)
}

function startPeriodicCachePrune() {
  if (cachePruneId) clearInterval(cachePruneId)
  cachePruneId = setInterval(() => config.cache.purgeStale(), config.dnsIdleTtlMs)
}

function getStats() {
  stats.dnsEntries = config.cache.size
  return stats
}

function getDnsCacheEntries() {
  return Array.from(config.cache.values())
}

// const dnsEntry = {
//   host: 'www.amazon.com',
//   ips: [
//     '52.54.40.141',
//     '34.205.98.207',
//     '3.82.118.51',
//   ],
//   nextIdx: 0,
//   lastUsedTs: 1555771516581, Date.now()
//   updatedTs: 1555771516581,
// }

function registerInterceptor(axios) {
  if (config.disabled || !axios || !axios.interceptors) return // supertest
  axios.interceptors.request.use(async (reqConfig) => {
    try {
      let url
      if (reqConfig.baseURL) {
        url = URL.parse(reqConfig.baseURL)
      } else {
        url = URL.parse(reqConfig.url)
      }
      reqConfig.metadata = { startTime: new Date()}

      if (net.isIP(url.hostname)) return reqConfig // skip

      reqConfig.headers.Host = url.hostname // set hostname in header

      url.hostname = await getAddress(url.hostname)
      delete url.host // clear hostname

      if (reqConfig.baseURL) {
        reqConfig.baseURL = URL.format(url)
      } else {
        reqConfig.url = URL.format(url)
      }
    } catch (err) {
      recordError(err, `Error getAddress, ${err.message}`)
    }

    return reqConfig
  })
}

async function getAddress(host) {
  let dnsEntry = config.cache.get(host)
  if (dnsEntry) {
    ++stats.hits
    dnsEntry.lastUsedTs = Date.now()
    // eslint-disable-next-line no-plusplus
    const ip = dnsEntry.ips[dnsEntry.nextIdx++ % dnsEntry.ips.length] // round-robin
    config.cache.set(host, dnsEntry)
    return ip
  }
  ++stats.misses
  if (log.isLevelEnabled('debug')) log.debug(`cache miss ${host}`)

  const ips = await resolve(host)
  dnsEntry = {
    host,
    ips,
    nextIdx: 0,
    lastUsedTs: Date.now(),
    updatedTs: Date.now(),
  }
  // eslint-disable-next-line no-plusplus
  const ip = dnsEntry.ips[dnsEntry.nextIdx++ % dnsEntry.ips.length] // round-robin
  config.cache.set(host, dnsEntry)
  return ip
}

let backgroundRefreshing = false
async function backgroundRefresh() {
  if (backgroundRefreshing) return // don't start again if currently iterating slowly
  backgroundRefreshing = true
  try {
    config.cache.forEach(async (value, key) => {
      try {
        if (value.updatedTs + config.dnsTtlMs > Date.now()) {
          return // continue/skip
        }
        if (value.lastUsedTs + config.dnsIdleTtlMs <= Date.now()) {
          ++stats.idleExpired
          config.cache.delete(key)
          return // continue
        }

        const ips = await resolve(value.host)
        value.ips = ips
        value.updatedTs = Date.now()
        config.cache.set(key, value)
        ++stats.refreshed
      } catch (err) {
        // best effort
        recordError(err, `Error backgroundRefresh host: ${key}, ${stringify(value)}, ${err.message}`)
      }
    })
  } catch (err) {
    // best effort
    recordError(err, `Error backgroundRefresh, ${err.message}`)
  } finally {
    backgroundRefreshing = false
  }
}

/**
 *
 * @param host
 * @returns {*[]}
 */
async function resolve(host) {
  let ips
  try {
    ips = await dnsResolve(host)
    throw new Error('test')
  } catch (e) {
    let lookupResp = await dnsLookup(host, { all: true }) // pass options all: true for all addresses
    lookupResp = extractAddresses(lookupResp)
    if (!Array.isArray(lookupResp) || lookupResp.length < 1) throw new Error(`fallback to dnsLookup returned no address ${host}`)
    ips = lookupResp
  }
  return ips
}

// dns.lookup
// ***************** { address: '142.250.190.68', family: 4 }
// , { all: true } /***************** [ { address: '142.250.190.68', family: 4 } ]

function extractAddresses(lookupResp) {
  if (!Array.isArray(lookupResp)) throw new Error('lookup response did not contain array of addresses')
  return lookupResp.filter((e) => e.address != null).map((e) => e.address)
}

function recordError(err, errMesg) {
  ++stats.errors
  stats.lastError = err
  stats.lastErrorTs = new Date().toISOString()
  log.error(err, errMesg)
}


const instance = axios.create({
    baseURL: "https://cp.bromelia.vmware.com",
    timeout: 30000,
    headers: { "Content-Type": "application/json" }
})

instance.interceptors.response.use(undefined, async (err) => {
    const config = err.config
    const response = err.response
    const maxRetries = 3
    const backoffIntervals = [10000,20000,30000]
/*
    console.log(
    `Error: ${JSON.stringify(err)}. Status: ${response ? response.status : "unknown"}. Data: ${
        response ? JSON.stringify(response.data) : "unknown"
    }`
    )
*/    
    if (
        (response && response.status && Object.values([429,503]).includes(response.status)) ||
        err.code === "ECONNABORTED" ||
        err.code === "ECONNREFUSED" ||
        err.message === "Network Error"
    ) {
    // Not sure if this message is trustable or just something moxios made up

    const currentState = config["vib-retries"] || {}
    currentState.retryCount = currentState.retryCount || 0
    config["vib-retries"] = currentState

    const index =
        currentState.retryCount >= backoffIntervals.length ? backoffIntervals.length - 1 : currentState.retryCount
    let delay = backoffIntervals[index]

    if (response && response.headers && response.headers["Retry-After"]) {
        const retryAfter = Number.parseInt(response.headers["Retry-After"])
        if (!Number.isNaN(retryAfter)) {
        delay = Number.parseInt(response.headers["Retry-After"]) * 1000
        console.log(`Following server advice. Will retry after ${response.headers["Retry-After"]} seconds`)
        } else {
        console.log(`Could not parse Retry-After header value ${response.headers["Retry-After"]}`)
        }
    }

    if (currentState.retryCount >= maxRetries) {
        console.log("The number of retries exceeds the limit.")
        return Promise.reject(new Error(`Could not execute operation. Retried ${currentState.retryCount} times.`))
    } else {
        console.log(`Request to ${config.url} failed. Retry: ${currentState.retryCount}. Waiting ${delay}`)
        currentState.retryCount += 1
    }
    config.transformRequest = [data => data]

    return new Promise(resolve => setTimeout(() => resolve(instance(config)), delay))
    } else {
    return Promise.reject(err)
    }
})  

init()

let cachingEnabled = process.env.ENABLE_CACHING == 'true' || false

if (cachingEnabled) {
    console.log("Running with DNS caching enabled")
    registerInterceptor(instance)
} else {
    console.log("Running with DNS caching disabled")
    instance.interceptors.request.use(async (reqConfig) => {
        reqConfig.metadata = { startTime: new Date()}
        return reqConfig
      })    
}

let runs = process.env.RUNS || 1000
let delay = process.env.DELAY || 1000

let i
for (i=0;i<runs;i++) {
    try {
        const response = await instance.get(`/v1/execution-graphs/aaa`, { // does not matter. We are interested in the HTTP response
        })
        console.log("Got a response!!")
    } catch (err) {
        if (axios.isAxiosError(err) && err.response) {
        if (err.response.status === 404) {
            const errorMessage = err.response.data
            ? err.response.data.detail
            : `Could not find execution graph with id ${executionGraphId}`
            console.log(errorMessage)
            throw new Error(errorMessage)
        } else if (err.response.status === 401) {
            err.config.metadata.endTime = new Date();
            err.duration = err.config.metadata.endTime - err.config.metadata.startTime;
            console.log(`Got a response from server ${err.response.status}. Duration: ${err.duration}ms`);
        
        } else {
            throw err
        }
        } else {
            throw err
        }
    }
    await new Promise(resolve => setTimeout(resolve, delay));
}

process.exit(0)
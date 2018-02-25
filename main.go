package main

import (
  "crypto"
  "crypto/elliptic"
  "crypto/ecdsa"
  "crypto/rand"
  "crypto/tls"
  "crypto/x509"
  "encoding/hex"
  "encoding/json"
  "errors"
  "log"
  "io/ioutil"
  "github.com/xenolf/lego/acme"
  "net/http"
  "net/url"
  "net/http/httputil"
  "sync"
)

type JSONSerializablePrivateKey struct {
  Key *ecdsa.PrivateKey
}

type User struct {
  Email string
  Registration *acme.RegistrationResource
  Key JSONSerializablePrivateKey
}

func (u User) GetEmail() string { return u.Email }

func (u User) GetRegistration() *acme.RegistrationResource { return u.Registration }
func (u User) GetPrivateKey() crypto.PrivateKey { return u.Key.Key }

func (jspk JSONSerializablePrivateKey) MarshalJSON() ([]byte, error) {
  bytes, err := x509.MarshalECPrivateKey(jspk.Key)
  if err != nil {
    return []byte{}, err
  }

  return json.Marshal(string(hex.EncodeToString(bytes)))
}

func (jspk *JSONSerializablePrivateKey) UnmarshalJSON(payload []byte) error {
  hexstring := ""
   err := json.Unmarshal(payload, &hexstring)
  if err != nil {
    return err
  }

  bytes, err := hex.DecodeString(hexstring)
  if err != nil {
    return err
  }

  key, err := x509.ParseECPrivateKey(bytes)

  jspk.Key = key

  return err
}


func ReadJSON(filename string, target interface{}) error {
  data, err := ioutil.ReadFile(filename)

  if err != nil {
    return err
  }

  return json.Unmarshal(data, target)
}

func NewClient(endpoint string, filename string, email string) (*acme.Client, error) {
  user := User{}
  err := ReadJSON(filename, &user)
  if err != nil {
    log.Println(err)
    pkey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
    if err != nil {
      return nil, err
    }

    user = User{Email: email, Key: JSONSerializablePrivateKey{Key: pkey}}
  }

  client, err := acme.NewClient(endpoint, &user, acme.EC384)
  if err != nil {
    return nil, err
  }

  if user.Registration == nil {
    reg, err := client.Register()
    if err != nil {
      return nil, err
    }

    user.Registration = reg

    payload, err := json.Marshal(user)
    if err != nil {
      return nil, err
    }

    err = ioutil.WriteFile(filename, payload, 0600)
    if err != nil {
      return nil, err
    }
  }

  log.Println("pkey")
  log.Println(user.Key.Key)

  client.AgreeToTOS()

  return client, err
}

type Settings struct {
  Proxies []struct {
    Domains []string `json:"domains"`
    Target string `json:"target"`
  } `json:"proxies"`
}

func (s *Settings) GetTarget(serverName string) (*url.URL, error) {
  for _, proxy := range s.Proxies {
    for _, domain := range proxy.Domains {
      if domain == serverName {
        return url.Parse(proxy.Target)
      }
    }
  }

  return nil, errors.New("unknown server name")
}

type CertificateStore struct {
  lock sync.RWMutex
  certificates map[string]*tls.Certificate
}

func (cs *CertificateStore) GetCertificate(serverName string) *tls.Certificate {
  cs.lock.RLock()
  defer cs.lock.RUnlock()

  return cs.certificates[serverName]
}

func (cs *CertificateStore) SetCertificate(serverNames []string, cert *tls.Certificate) {
  cs.lock.Lock()
  defer cs.lock.Unlock()

  for _, serverName := range serverNames {
    cs.certificates[serverName] = cert
  }
}

func main() {
  client, err := NewClient("https://acme-staging.api.letsencrypt.org/directory", "tmp/user.json", "hugo.peixoto@gmail.com")
  log.Println(err)

  client.SetHTTPAddress(":80")

  settings := Settings{}

  err = ReadJSON("tmp/proxy.json", &settings)
  log.Println(err)

  domains := []string{"speakers-staging.porto.codes"}

  certs, failures := client.ObtainCertificate(domains, true, nil, false)

  if len(failures) > 0 {
    log.Println(failures)
    return
  }

  cert, err := tls.X509KeyPair(certs.Certificate, certs.PrivateKey)

  //_, err = client.RenewCertificate(certRes, true, false)
  log.Println(err)

  server := http.Server{
    Addr: ":https",
    TLSConfig: &tls.Config{
      GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
        return &cert, nil
      },
    },
    Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      target, err := settings.GetTarget(r.Host)

      if err != nil {
        w.WriteHeader(404)
        w.Write([]byte("unknown domain "))
        w.Write([]byte(r.Host))
        w.Write([]byte("\n"))
      } else {
        httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
    }
    }),
  }

  err = server.ListenAndServeTLS("", "")
  log.Println(err)
}

package licenseclient

import (
	"time"
)

const (
	RegisterRequest          = "/ls/license/register"
	HeartBeatRequest         = "/ls/handshake"
	HeartBeatPingRequest     = "/ping"
	BlankString              = ""
	LastTimeBlank            = "temp"
	TimeDiffValid            = "true"
	TimeDiffInvalid          = "fals"
	FileAlreadyExistError    = "file already exist, can not create duplicate"
	TDuration                = 30
	//update time in table one time per hour(60 minutes),then 55,65 appear, here we use second as the unit
	MinDuration              = 0
	MaxDuration              = 600
	ToleranceDays            = 5
	FilePath                 = "f.json"
	OKString                 = "OK"
	NotOKString              = "NK"
	TrueString               = "true"
	MethodNotAllowedError    = "the method not allowed for this api "
	ServerInternalError      = "the internal server error"
	ClientRequestError       = "the client request error"
	GoStandardTime           = "2006-01-02"
	LicenseEnableStatus      = "enable"
	LicenseDisableStatus     = "disable"
	LicenseMidStatus         = "midStatus"
	Kstring                  = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8uMnRS01tpRWG1URGmEfYoJgy
9ZOZ56euqsBrsoFX0Bf9lyr0wlXNo4v2HE5tg1+NdZb7yQ0eUT+l9aNYdQwt8Hta
ObqiOC336h0OXaoXR6M2DM67xWeWv8EZeBLzpH+oMRg2SzperMmaUO78YLGgijUF
cNILlMAAMWYtKeaiTwIDAQAB
-----END PUBLIC KEY-----`
)

type BadResponse struct {

}

type CommonResponse struct {
	Code   int         `json:"code"`
	Enable bool        `json:"enable"`
	ErrMsg string      `json:"errMsg"`
	Data   interface{} `json:"data"`
}

type RegisterBody struct {
	ClientID      string
	ClientName    string `json:"client_name"`
	RegisterCode  string `json:"register_code"`
	CommonModel
}

type CommonModel struct {
	CreatedTime time.Time
}

type EncryptedBody struct {
	EncryptedData string `json:"encrypteddata"`
	Signature     string `json:"signature"`
}

type ServerResponse struct {
	Code   int         `json:"code"`
	Enable bool        `json:"enable"`
	ErrMsg string      `json:"errMsg"`
	Data   interface{} `json:"data"`
}

//RC : register code
type RCOnline struct {
	S             string    //This is the SN get from server end
	D             string    //This is the Domain which get from client end, the corresponding ENV key is SsoExternalDomain
	//T             int64     //current time
}

type RCOffline struct {
	//S             string    //This is the SN get from server end
	D             string    //This is the Domain which get from client end, the corresponding ENV key is SsoExternalDomain
	//T             int64     //current time
}

type CheckRes struct {
	Value         bool   `json:"value"`
	RegularCheck  string `json:"regular_check"`
	GetResTime    int64  `json:"get_res_time"`
	PartNumber    string `json:"part_number"`
	HashList      []string
}

type FileResult struct {
	LicenseName   string `json:"licensename"`
	CustomerName  string `json:"customname"`
	ClusterCode   string `json:"clustercode"`
	ClientDomain  string `json:"clientdomain"`
	PartNumber    string `json:"partnumber"`
	Version       string `json:"version"`
	EffectiveTime string `json:"effictivetime"`
	ExpiredTime   string `json:"expiredtime"`
	SeriesNumber  string
	//For hash check
	HashList      []string
	Description   string `json:"description"`
}

type IdInfo struct {
	IdA           string
	IdB           string
	IdC           string
	IDR           string
	Used          bool   //`gorm:"default:'f'"`
	Method        int8   //`gorm:"default:'0'"`//1:online; 2:offline; 0:unregister
	Content       string
	Sig           string
}

type SNbody struct {
	SN            string `json:"sn"`
}

type ResIDInfo struct {
	Result        string //the result
	CurrentTime   int64  //current time when generate the result
}

//The heartBeat body sent to server
type HeartBeatBody struct {
    SendTime      int64
    FileResult
}

type HBRequestBody struct {
	Data          string
}

type HBReturnBody  struct {
	Data          string
}

type HeartBeatResponse struct {
	ClientID      string //
	LicenseStatus string
}
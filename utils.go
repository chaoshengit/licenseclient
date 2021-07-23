package licenseclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/wonderivan/logger"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"
	"crypto/sha256"
    "encoding/hex"
    "io"
)


//Global variable
var ResultContainer = [3]string{"true","fals","temp"}
var PwdKey = []byte("wiugfoqliwdhgcvo")

func ResponseHandler(w http.ResponseWriter, outputContent []byte,code int) {
	w.Header().Set("Server", "An agent")
	w.Header().Set("Content-Type", "application/json")
	//add return code, need to put before w.Write
	w.WriteHeader(code)
	_, err := w.Write(outputContent)
	if err != nil {
		logger.Error("Write response content error: ",err.Error())
	}
	return
}

//handle the common bad response
func SendBadResponse(error error) []byte {
	response := CommonResponse{
		Code: -1,
		ErrMsg: error.Error(),
	}
	logger.Error(error.Error())
	responseData, _:= json.Marshal(response)
	return responseData
}

//generate the client id
func GenRcode(sn string) string {
	c := RC{
		S: sn,
		D: os.Getenv("SsoExternalDomain"),
		T: GetCurrentTime(),
	}

	Db,_ := json.Marshal(c)
	clientId, err := EncryptByAes(Db)
	if err != nil {
		return BlankString
	}
	return clientId

}

//Verify the legality for the auth Certification file
func GetFileRes(PGDB *GormDB) CheckRes {
	tres := CheckRes{
		Value: true,
	}
	fres := CheckRes{
		Value: false,
	}

	err,data := PGDB.ReadAndDecryptFile(FilePath)
	if err != nil {
		return fres
	}

	if VerifyEffectiveTime(data.EffectiveTime) != TrueString {
		return fres
	}
	res := PGDB.VerifyData(data)
	//following print only for test. after test, need to be deleted
	logger.Info("This is the result of VerifyData:", res)
	if res == TrueString {
        //_ = PGDB.UpdateUseState(data.ClusterCode)
        tres.PartNumber = data.PartNumber
        tres.HashList   = data.HashList
		return tres
	}
	return fres
}

//Tool function: check whether the file exist in the specific path
func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

//Tool function: write encrypted content to the Certification file
func write(LicenseContent interface{}, client RegisterBody) error {
	//genTime := time.Now().Unix()
	logger.Info("This is the file for: ", client.ClientName)
	fileCheckRes, _  := PathExists(FilePath)
	if fileCheckRes {return errors.New(FileAlreadyExistError)}
	LicenseContentB, err1 := json.Marshal(LicenseContent)
	if err1 != nil {
		return err1
	}

	err2 := ioutil.WriteFile(FilePath, LicenseContentB, os.ModeAppend)
	if err2 != nil {
		return err2
	}
	return nil
}

//Read the encrypted file in the path
func ReadFile(licensePath string) (error, EncryptedBody){
	var dfile EncryptedBody
	logger.Info("Begin to phrase the license file.")
	content, err := ioutil.ReadFile(licensePath)
	if err != nil {
		logger.Error("Read the json file failed", err.Error())
		return err, EncryptedBody{}
	}

	err1 := json.Unmarshal(content, &dfile)
	if err1 != nil {
		logger.Error("Unmarshal the encrypt license failed")
		return err, EncryptedBody{}
	}
	logger.Error("End to phrase the license file.")
	return nil, dfile
}

func (PGDB *GormDB)checkLicInDB() (error, EncryptedBody) {
	var dContent EncryptedBody
	err, result := PGDB.GetCRecord()
	if err != nil {
		logger.Error("Obtain the content error: ", err.Error())
		return err, EncryptedBody{}
	}
	dContent = EncryptedBody{
		EncryptedData: result.Content,
		Signature: result.Sig,
	}
	return nil, dContent

}

func (GB *GormDB)ReadAndDecryptFile(path string) (error, FileResult) {
	var resultLicense FileResult
	var data,signature string
	exist, _ := PathExists(FilePath)
	if ! exist {
		err, result := GB.checkLicInDB()
		if err != nil {
			return err,FileResult{}
		}
		data = result.EncryptedData
		signature = result.Signature
	} else {
		err, encryptData := ReadFile(path)
		if err != nil {
			return err,FileResult{}
		}
		data = encryptData.EncryptedData
		signature = encryptData.Signature
	}
	
	err1 := RSAVerify([]byte(data), signature)
	if err1 != nil {
		logger.Error("Verify the signature failed: ", err1.Error())
		return err1, FileResult{}
	}

	decryptByte, err2 := DecryptByAes(data)
	if err2 != nil {
		logger.Error("Failed to get the license data: ", err2.Error())
		return err2, FileResult{}
	}

	err3 := json.Unmarshal(decryptByte,&resultLicense)
	if err3 != nil {
		logger.Error("Unmarshal license failed: ",err3.Error())
		return err3, FileResult{}
	}

	return nil, resultLicense
}

//Check whole data in file
func (GB *GormDB)VerifyData(data FileResult) (dataRes string) {
    result1 := GB.VerifyClusterCode(data.ClusterCode)
    result2 := VerifyValid(data.ExpiredTime)
	//following print only for test. after test, need to be deleted
	logger.Info("This is the result of result1: ", result1)
	logger.Info("This is the result of result2: ", result2)
    if result1 == OKString && result2 == OKString {
    	return "true"
	}
	return "false"
}
//Check the Cluster Code
func (PGDB *GormDB)VerifyClusterCode(data string) (OK string) {
	var res RC
	err, records := PGDB.GetCids()
	if err != nil {
		logger.Info("This is the error when check the client id: ", err.Error())
        return BlankString
	}

	if ! IsInclude(records,data) {
		logger.Error("The client id may be fake one, please check")
		return BlankString
	}

	resByte, err1 := DecryptByAes(data)
	if err1 != nil {
		logger.Error("Failed to decrypt the client id")
        return BlankString
	}

	err2 := json.Unmarshal(resByte, &res)
	if err2 != nil {
		logger.Error("The data inner client id may be wrong")
		return BlankString
	}

	if res.D != os.Getenv("SsoExternalDomain"){
		logger.Error("The domain is not match")
		return BlankString
	}

	if res.T <= GetCurrentTime() {
		return OKString
	}
	logger.Info("This is the last-current time :", res.T)
	return BlankString
}
//Check the Valid of the file
func VerifyValid(data string) (OK string) {
	logger.Info("This is the data in VerifyValid: ", data)
    T,err := time.Parse(GoStandardTime,data)
    if err != nil {
    	return BlankString
	}
    if T.Unix() - GetCurrentTime() > TDuration {
    	return OKString
	}
	return BlankString
}

//Check whether current time has exceed the expire time
func VerifyEffectiveTime(effectTimeStr string) (result string) {
	logger.Info("This is the time string :", effectTimeStr)
	effectTime, err := time.Parse("2006-01-02", effectTimeStr)
    if err != nil {
    	logger.Error("The format of the time str is invalid")
    	return BlankString
	}
	diffTime := effectTime.Sub(time.Now()).Hours()/24
	if diffTime > ToleranceDays {
		logger.Error("The license has not make effect")
		return BlankString
	}
    return TrueString
}

//record the first id record into db
func (PGDB *GormDB)RecordID(IDA string) (err error) {
	currentTime := GetCurrentTime()
	CurrentTimeString := strconv.FormatInt(currentTime,10)
	DString, err1 := EncryptByAes([]byte(CurrentTimeString))
	if err1 != nil {
		return err1
	}
	insertData := IdInfo{
		IdA: IDA,
		IdC: DString,
	}
	err2 := PGDB.insertCtoDB(insertData)
	if err2 != nil {
		return err2
	}
	//After generate the client id, initialize the IDR(result) in the table with blank of idB
	res := ResIDInfo{
		Result: LastTimeBlank,
		CurrentTime: GetCurrentTime(),
	}
	PGDB.MakeResDB(res,IDA)
	return nil
}

//Regular update the current time and last time in table
func (PGDB *GormDB)RegularUpdateC() {
	currentTime := GetCurrentTime()
	//convert an int64 timestamp number to string for decrypt
	CurrentTimeString := strconv.FormatInt(currentTime,10)
	DString , err := EncryptByAes([]byte(CurrentTimeString))
	if err != nil {
		logger.Error("There is some issue when deal the idC: ", err.Error())
	}
	err1 := PGDB.updateC(DString)
	if err1 != nil {
		logger.Error("There is some issue when deal the idC in DB: ", err1.Error())
	}
}

//Regular check the duration between current time and last time
func (PGDB *GormDB)RegularCheckC() {
//There has three condition 1.no record found 2.only idA  and idC there 3.all ids there.
	err,id := PGDB.GetCRecord()
	if err == nil {
		if id.IdC == BlankString {
			logger.Error("IdC value error")
			return
		}
		if id.IdB == BlankString {
			res := ResIDInfo{
				Result: LastTimeBlank,
				CurrentTime: GetCurrentTime(),
			}
			PGDB.MakeResDB(res,id.IdA)
			logger.Error("IdB value error")
			return
		}
        idBByte, err1 := DecryptByAes(id.IdB)
        if err1 != nil {
        	logger.Error("IdB value error1")
		}
        idCByte, err2 := DecryptByAes(id.IdC)
		if err2 != nil {
			logger.Error("IdC value error1")
		}
        if err1 == nil && err2 == nil {
        	//here should be a struct including timestamp and result
			result := CheckValidC(idBByte,idCByte)
			logger.Info("This is the check result in RegularCheckC: ", result)
			res := ResIDInfo{
				Result: result,
				CurrentTime: GetCurrentTime(),
			}
			PGDB.MakeResDB(res, id.IdA)
		}
	}
}

//Check whether the time in idB and idC column is valid
func CheckValidC(idB ,idC []byte) (checkRes string){
	//convert a timestamp string to int64
	lastTime, err1 := strconv.Atoi(string(idB))
	if err1 != nil {
		return TimeDiffInvalid
	}
	current, err2 := strconv.Atoi(string(idC))
	if err2 != nil {
		return TimeDiffInvalid
	}
	logger.Info("This is the last time and current time: ", lastTime, "-", current)
	//Considering Service Interruption scene, the max duration is incalculable,then will not judge it
    if current - lastTime < MinDuration {
    	return TimeDiffInvalid
	}
	return TimeDiffValid
}

//After upload license, if license file is not valid, need to delete it
func RemoveFile(filePath string) error {
	commandString := fmt.Sprintf("rm -rf %s", filePath)
	isExist,_ := PathExists(filePath)
	if ! isExist {return nil}
	out,err:= exec.Command("/bin/bash","-c", commandString).Output()
	if err != nil {
		return err
	}
	logger.Info("This is output for command remove file: ", out)
	return nil
}

//For online register scene, verify the input parameter: SN
func VerifySN(sn string) (result bool) {
	if sn == BlankString {
		return false
	}
	reg := regexp.MustCompile("([A-Z0-9]{8}-){3}[A-Z0-9]{8}")
	if ! reg.MatchString(sn) {
		return false
	}
	return true
}

/*For online register scene,check valid for current license,
if within effect time, not permit to do online register.
 */
func CheckLicense(){}

func IsInclude(items []string, item string) bool {
	for _, I := range items {
		if I == item {
			return true
		}
	}
	return false
}

//Obtain the Regular time check result in DB
func (PGDB *GormDB)CheckResInDB() (res string) {
	var CheckRes ResIDInfo
	resSet := ResultContainer[:]
	err,idRecord := PGDB.GetCRecord()
	if err != nil {
		logger.Error("It is checkResInDB error: ", err.Error())
		return NotOKString
	}

	IDRByte, err1 := DecryptByAes(idRecord.IDR)
	if err1 != nil {
		logger.Error("It is checkResInDB error1: ", err1.Error())
		return NotOKString
	}
	logger.Info("This is the IDRByte in CheckResInDB(): ", string(IDRByte))
	err2 := json.Unmarshal(IDRByte, &CheckRes)
	if err2 != nil {
		logger.Error("It is checkResInDB error2: ", err2.Error())
		return NotOKString
	}
	logger.Info("This is the CheckRes in CheckResInDB(): ", CheckRes)
	if ! IsInclude(resSet,CheckRes.Result) {
		logger.Error("It is checkResInDB error3")
		return NotOKString
	}

	if ! CompareWithCurrentTime(CheckRes.CurrentTime,ToleranceDays*24*3600) {
		logger.Error("It is checkResInDB error4")
		return NotOKString
	}
	logger.Info("this is the CheckRes in function CheckResInDB: ", CheckRes)
	if CheckRes.Result == "true" || CheckRes.Result == "temp" {
		return OKString
	}
	return NotOKString
}

//Tool function: for update the regular result in database
func (PGDB *GormDB)MakeResDB(res ResIDInfo, IdA string) {
	resultByte, err3 := json.Marshal(res)
	if err3 != nil {
		logger.Error("issue happened in check:", err3.Error())
	}
	result, err4 := EncryptByAes(resultByte)
	if err4 != nil {
		logger.Error("issue happened in check1: ", err4.Error())
	}
	err5 := PGDB.updateResult(result, IdA)
	if err5 != nil {
		logger.Error("issue happened in check2: ", err5.Error())
	}
}

//Tool function: compare the current time with the input time
func CompareWithCurrentTime(recordTime int64, maxTimeGap int64) bool {
	if GetCurrentTime() - recordTime > maxTimeGap {
		logger.Error("The time gap has exceed the max time gap")
		return false
	}
	return true
}

func GetCurrentTime() int64{
	return time.Now().Unix()
}

//Check connection between client with server
func CheckConnect() bool {
	timeout := time.Duration(5 * time.Second)
	client := http.Client{
		Timeout: timeout,
	}
	_, err := client.Get("http://www.msftconnecttest.com/connecttest.txt")
	if err != nil {
		logger.Error("The connection error between client and server: ", err.Error())
		return false
	}
	return true
}

//Send heart beat to license server
func (GB *GormDB)SendHeartBeat() {
	logger.Info("Begin to send the heartbeat.")
	if ! CheckConnect() {
		return
	}
	err,data := GB.ReadAndDecryptFile(FilePath)
    if err != nil {
		logger.Error("Read file failed: ", err.Error())
		return
	}

	body := HeartBeatBody{
    	SendTime: GetCurrentTime(),
    	FileResult: data,
	}
	bodyByte,_ := json.Marshal(body)
	sendString, err1 := EncryptByAes(bodyByte)
	if err1 != nil {
		logger.Error("Error occur when send HB: ", err1.Error())
		return
	}
	sendBody := HBRequestBody{
		Data: sendString,
	}

	sendByte, _ := json.Marshal(sendBody)
	serverIP := os.Getenv("ServerIP")
	url := serverIP + HeartBeatRequest
	logger.Info("This is the request url: ", url)
	httpClient := &http.Client{}
	httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	req, err3 := http.NewRequest("POST",url,bytes.NewReader(sendByte))
	if err3 != nil {
		logger.Error("Make the new request error: ", err3.Error())
		return
	}
	_, err4 := httpClient.Do(req)
	if err4 != nil {
		logger.Error("Request the server error: ", err4.Error())
		return
	}
}

//Tool func: This is the interface to regular check id_infos table
func LicenseCheck(db *GormDB) {
	ticker := time.NewTicker(5 * TDuration * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		logger.Info("Regular check begin")
		if db.CheckC() {
			db.RegularCheckC()
		}
		logger.Info("Regular check end")
	}
}

//Tool func: This is the interface to regular check id_infos table
func LicenseUpdate(db *GormDB) {
	ticker := time.NewTicker(10 * TDuration * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		logger.Info("Regular update begin")
		if db.CheckC() {
			db.RegularUpdateC()
			db.SendHeartBeat()
		}
		logger.Info("Regular update end")
	}
}

//Tool func: This is the interface to send license heartbeat
func LicenseHBSend(db *GormDB) {
	ticker := time.NewTicker(10 * TDuration * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		db.SendHeartBeat()
	}
}

func ParseResInDB(GB *GormDB) (error, bool) {
	logrus.Println("Begin to parse the res in db")
	var ResInfo ResIDInfo
	var resBool bool
	err, id := GB.GetCRecord()
	if err != nil {
		return err,false
	}

	resByte, err1 := DecryptByAes(id.IDR)
	if err1 != nil {
		return err,false
	}

	err2 := json.Unmarshal(resByte,&ResInfo)
	if err2 != nil {
		return err,false
	}

	timeDiff := GetCurrentTime() - ResInfo.CurrentTime
	if  timeDiff > 6 * 24 * 3 * TDuration || timeDiff < 0 {
		logger.Error("Found expired based on the time diff reason")
		return err,false
	}
	if ResInfo.Result == LastTimeBlank || ResInfo.Result == TimeDiffValid {
		resBool = true
	} else {
		resBool = false
	}

	return nil,resBool
}

//For license client hash check
func GetHashRes(path string)  string {
	res,_ := PathExists(path)
	if ! res {
		logger.Error("The bin file is not exist, please check.")
		return BlankString
	}
    file, err := os.Open(path)
	defer file.Close()
    if err == nil {
        hashInstance := sha256.New()
        _, err := io.Copy(hashInstance, file)
        if err == nil {
            hashed := hashInstance.Sum(nil)
            hashString := hex.EncodeToString(hashed)
            return hashString
        } else {
            return BlankString
        }
    } else {
        return BlankString
    }
}





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
	logrus.Println(error.Error())
	responseData, _:= json.Marshal(response)
	return responseData
}

//generate the client id
func GenRcode(sn string) string {
	c := RC{
		S: sn,
		D: os.Getenv("DOMAIN"),
		T: GetCurrentTime(),
	}
/*    DT, _ := EncryptByAes([]byte(string(c.T)))
	_ = PGDB.insertCtoDB(DT)*/
	Db,_ := json.Marshal(c)
	clientid, err := EncryptByAes(Db)
	if err != nil {
		return BlankString
	}
	return clientid

}

//Verify the legality for the auth Certification file
func (PGDB *GormDB)GetFileRes() CheckRes {
	tres := CheckRes{
		Value: true,
	}
	fres := CheckRes{
		Value: false,
	}
	result,_ := PathExists(FilePath)
	if ! result {
		return fres
	}
	err,data := ReadAndDecryptFile(FilePath)
	if err != nil {
		return fres
	}
    fmt.Println("This is the data from server: ",data)
	if VerifyEffectiveTime(data.EffectiveTime) != TrueString {
		return fres
	}
	res := PGDB.VerifyData(data)
	//following print only for test. after test, need to be deleted
	fmt.Println("this is the result of VerifyData",res)
	if res == TrueString {
        _ = PGDB.UpdateUseState(data.ClusterCode)
        tres.PartNumber = data.PartNumber
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
	logrus.Info("This is the file for: ",client.ClientName)
	fileCheckRes,_  := PathExists(FilePath)
	if fileCheckRes {return errors.New(FileAlreadyExistError)}
	LicenseContentB, err1 := json.Marshal(LicenseContent)
	if err1 != nil {
		return err1
	}

	err2 := ioutil.WriteFile(FilePath,LicenseContentB,os.ModeAppend)
	if err2 != nil {
		return err2
	}
	return nil
}

//Read the encrypted file in the path
func ReadFile(licensepath string) (error,EncryptedBody){
	var dfile EncryptedBody
	logrus.Println("Begin to phrase the license file.")
	content, err := ioutil.ReadFile(licensepath)
	if err != nil {
		logrus.Println("read the json file failed",err)
		return err,EncryptedBody{}
	}

	err1 := json.Unmarshal(content, &dfile)
	if err1 != nil {
		logrus.Println("Unmarshal the encrypt license failed")
		return err,EncryptedBody{}
	}
	logrus.Println("End to phrase the license file.")
	return nil, dfile
}

func ReadAndDecryptFile(path string) (error, FileResult) {
	var resultLicense FileResult
	err,encryptdata := ReadFile(path)
	if err != nil {
		return err,FileResult{}
	}

	data := encryptdata.EncryptedData
	signature := encryptdata.Signature
	err1 := RSAVerify([]byte(data),signature)
	if err1 != nil {
		logrus.Println("Verify the signature failed.")
		return err1, FileResult{}
	}

	decryptByte, err2 := DecryptByAes(data)
	if err2 != nil {
		logrus.Println("Failed to get the license data")
		return err2, FileResult{}
	}

	err3 := json.Unmarshal(decryptByte,&resultLicense)
	if err3 != nil {
		logrus.Println("Unmarshal license failed")
		return err3, FileResult{}
	}

	return nil, resultLicense
}

//Check whole data in file
func (GB *GormDB)VerifyData(data FileResult) (dataRes string) {
    result1 := GB.VerifyClusterCode(data.ClusterCode)
    result2 := VerifyValid(data.ExpiredTime)
	//following print only for test. after test, need to be deleted
	fmt.Println("this is the result of result1: ",result1)
	fmt.Println("this is the result of result2: ",result2)
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
		logrus.Info("This is the error: ",err.Error())
        return BlankString
	}

	if ! IsInclude(records,data) {
		fmt.Println("111111111111")
		return BlankString
	}

	resByte, err1 := DecryptByAes(data)
	if err1 != nil {
		fmt.Println("22222222222")
        return BlankString
	}

	err2 := json.Unmarshal(resByte,&res)
	if err2 != nil {
		fmt.Println("333333333333")
		return BlankString
	}

	if res.D != os.Getenv("DOMAIN"){
		fmt.Println("444444444444")
		return BlankString
	}
	fmt.Println("This is the res.T :",res.T)
	if res.T <= GetCurrentTime() {
		fmt.Println("555555555555")
		return OKString
	}
		return BlankString
}
//Check the Valid of the file
func VerifyValid(data string) (OK string) {
	fmt.Println("this is the data in VerifyValid: ",data)
    T,err := time.Parse(GoStandardTime,data)
    if err != nil {
    	return BlankString
	}
	fmt.Println("This is the T.Unix(): ",T.Unix())
    if T.Unix() - GetCurrentTime() > TDuration {
		fmt.Println("77777777777")
    	return OKString
	}
	return BlankString
}

//Check whether current time has exceed the expire time
func VerifyEffectiveTime(effectTimeStr string) (result string) {
	fmt.Println("this is the time string :",effectTimeStr)
	effectTime, err := time.Parse("2006-01-02",effectTimeStr)
    if err != nil {
    	logrus.Error("The format of the time str is invalid")
    	return BlankString
	}
	diffTime := effectTime.Sub(time.Now()).Hours()/24
	if diffTime > ToleranceDays {
		logrus.Info("The client time may have been ")
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
		logrus.Println("There is some issue when deal the idC")
	}
	err1 := PGDB.updateC(DString)
	if err1 != nil {
		logrus.Println("There is some issue when deal the idC in DB")
	}
}

//Regular check the duration between current time and last time
func (PGDB *GormDB)RegularCheckC() {
//There has three condition 1.no record found 2.only idA  and idC there 3.all ids there.
	err,id := PGDB.GetCRecord()
	if err == nil {
		if id.IdC == BlankString {
			fmt.Println("IdC value error")
			return
		}
		if id.IdB == BlankString {
			res := ResIDInfo{
				Result: LastTimeBlank,
				CurrentTime: GetCurrentTime(),
			}
			PGDB.MakeResDB(res,id.IdA)
			fmt.Println("IdB value error")
			return
		}
        idBByte, err1 := DecryptByAes(id.IdB)
        if err1 != nil {
        	fmt.Println("IdB value error1")
		}
        idCByte, err2 := DecryptByAes(id.IdC)
		if err2 != nil {
			fmt.Println("IdC value error1")
		}
        if err1 == nil && err2 == nil {
        	//here should be a struct including timestamp and result
			result := CheckValidC(idBByte,idCByte)
			fmt.Println("This is the check result in RegularCheckC: ",result)
			res := ResIDInfo{
				Result: result,
				CurrentTime: GetCurrentTime(),
			}
			PGDB.MakeResDB(res,id.IdA)
		}
	}
}

//Check whether the time in idB and idC column is valid
func CheckValidC(idB ,idC []byte) (checkRes string){
	//convert a timestamp string to int64
	lasttime, err1 := strconv.Atoi(string(idB))
	if err1 != nil {
		return TimeDiffInvalid
	}
	current, err2 := strconv.Atoi(string(idC))
	if err2 != nil {
		return TimeDiffInvalid
	}
	fmt.Println("This is the last time and current time:",lasttime,"-",current)
	//Considering Service Interruption scene, the max duration is incalculable,then will not judge it
    if current - lasttime < MinDuration {
    	return TimeDiffInvalid
	}
	return TimeDiffValid
}

//After upload license, if license file is not valid, need to delete it
func RemoveFile(filePath string) error {
	commandString := fmt.Sprintf("rm -rf %s",filePath)
	isExist,_ := PathExists(filePath)
	if ! isExist {return nil}
	out,err:= exec.Command("/bin/bash","-c",commandString).Output()
	if err != nil {
		return err
	}
	fmt.Println("This is out: ",out)
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
		fmt.Println("It is checkResInDB error")
		return NotOKString
	}

/*	if idRecord.IDR == "" {

	}*/

	IDRByte, err1 := DecryptByAes(idRecord.IDR)
	if err1 != nil {
		fmt.Println("It is checkResInDB error1")
		return NotOKString
	}
	fmt.Println("This is the IDRByte in CheckResInDB(): ",string(IDRByte))
	err2 := json.Unmarshal(IDRByte, &CheckRes)
	if err2 != nil {
		fmt.Println("It is checkResInDB error2")
		return NotOKString
	}
    fmt.Println("This is the CheckRes in CheckResInDB(): ",CheckRes)
	if ! IsInclude(resSet,CheckRes.Result) {
		fmt.Println("It is checkResInDB error3")
		return NotOKString
	}

	if ! CompareWithCurrentTime(CheckRes.CurrentTime,ToleranceDays*24*3600) {
		fmt.Println("It is checkResInDB error4")
		return NotOKString
	}
	fmt.Println("this is the CheckRes in function CheckResInDB: ",CheckRes)
	if CheckRes.Result == "true" || CheckRes.Result == "temp" {
		return OKString
	}
	return NotOKString
}

//Tool function: for update the regular result in database
func (PGDB *GormDB)MakeResDB(res ResIDInfo, IdA string) {
	resultByte, err3 := json.Marshal(res)
	if err3 != nil {
		logrus.Println("issue happened in check:", err3)
	}
	result, err4 := EncryptByAes(resultByte)
	if err4 != nil {
		logrus.Println("issue happened in check1: ", err4)
	}
	err5 := PGDB.updateResult(result, IdA)
	if err5 != nil {
		logrus.Println("issue happened in check2: ", err5)
	}
}

//Tool function: compare the current time with the input time
func CompareWithCurrentTime(recordTime int64,maxTimeGap int64) bool {
	if GetCurrentTime() - recordTime > maxTimeGap {
		fmt.Println("The time gap has exceed the max time gap")
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
	_, err := client.Get("https://www.baidu.com")
	if err != nil {
		fmt.Println("The connection error between client and server, ",err.Error())
		return false
	}
	return true
}

//Send heart beat to license server
func SendHeartBeat() {
    fmt.Println("Begin to send the heartbeat.")
	if ! CheckConnect() {
		return
	}
	err,data := ReadAndDecryptFile(FilePath)
    if err != nil {
    	fmt.Println("Read file failed")
		return
	}

	body := HeartBeatBody{
    	SendTime: GetCurrentTime(),
    	FileResult: data,
	}
	bodyByte,_ := json.Marshal(body)
	sendString,err1 := EncryptByAes(bodyByte)
	if err1 != nil {
		fmt.Println("error occur when send HB")
		return
	}
	sendBody := HBRequestBody{
		Data: sendString,
	}

	sendByte, _ := json.Marshal(sendBody)
	serverIP := os.Getenv("ServerIP")
	url := serverIP + HeartBeatRequest
	logger.Info("This is the request url: ",url)
	httpClient := &http.Client{}
	httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	req, err3 := http.NewRequest("POST",url,bytes.NewReader(sendByte))
	if err3 != nil {
        fmt.Println("Make the new request error: ",err3.Error())
		return
	}
	_, err4 := httpClient.Do(req)
	if err4 != nil {
		fmt.Println("Request the server error: ",err4.Error())
		return
	}
}

//Tool func: This is the interface to regular check id_infos table
func LicenseCheck(db *GormDB) {
    //fmt.Printf("This is the type of duration: %T",TDuration)
	ticker := time.NewTicker(5 * TDuration * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		logrus.Println("Regular check begin")
		if db.CheckC() {
			db.RegularCheckC()
		}
		logrus.Println("Regular check end")
	}
}

//Tool func: This is the interface to regular check id_infos table
func LicenseUpdate(db *GormDB) {
	ticker := time.NewTicker(10 * TDuration * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		logrus.Println("Regular update begin")
		if db.CheckC() {
			db.RegularUpdateC()
			SendHeartBeat()
		}
		logrus.Println("Regular update end")
	}
}

//Tool func: This is the interface to send license heartbeat
func LicenseHBSend() {
	ticker := time.NewTicker(10 * TDuration * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		SendHeartBeat()
	}
}


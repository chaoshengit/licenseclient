package licenseclient

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/wonderivan/logger"
	"io/ioutil"
	"net/http"
	"os"
)

//type dbCli gorm.DB

func (GB *GormDB)RegisterCall(client RegisterBody) (error, CommonResponse) {
	var responseServer CommonResponse
	//var ResponseBody EncryptedBody
	client.ClientID = GenRcodeOnline(client.RegisterCode)
	logger.Info("This is the client id generate at client: ", client.ClientID)
	err2 := GB.RecordID(client.ClientID)
	if err2 != nil {
		logger.Error("Record ID when register online error: ", err2.Error())
		return err2, CommonResponse{}
	}
	clientByte, _ := json.Marshal(client)
	serverIP := os.Getenv("LicenseServerIP")
	url := serverIP + RegisterRequest
	logger.Info("The register request url is: ", url)
	httpClient := &http.Client{}
	httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	req, err3 := http.NewRequest("POST", url, bytes.NewReader(clientByte))
	if err3 != nil {
		logger.Error("Create request for register error: ", err3.Error())
		return err3, CommonResponse{}
	}
	serverResponse, err4 := httpClient.Do(req)
	if err4 != nil {
		logger.Error("Request for register error: ", err4.Error())
		return err4, CommonResponse{}
	}
	result, err5 := ioutil.ReadAll(serverResponse.Body)
	logger.Debug("This is the online register response data: ", string(result))
	if err5 != nil {
		logger.Error("Get server response error: ", err5.Error())
		return err5, CommonResponse{}
	}
	err6 := json.Unmarshal(result, &responseServer)
	if err6 != nil {
		logger.Error("Parse server response error: ", err6.Error())
		return err6, CommonResponse{}
	}

	if err8 := RemoveFile(FilePath); err8 != nil {
		logger.Error("Failed to handle the previous invalid license file.")
	}
    
	if responseServer.Data == nil {
		logger.Error("Get plain or nil data response from server.")
		return errors.New("get plain data error"), CommonResponse{}
	}
	dataRes, _ := responseServer.Data.(map[string]interface{})
	encryptedData, ok1 := dataRes["encrypteddata"].(string)
	sigNature, ok2 := dataRes["signature"].(string)
	if ! ok1 || ! ok2 {
		logger.Error("The element in dataRes is not the corresponding type")
	}
	err9 := GB.UpdateContent(client.ClientID, encryptedData, sigNature)
	if err9 != nil {
	    logger.Error("Update content for the id_infos item")
		return errors.New(ServerInternalError), CommonResponse{}
	}
	logger.Debug("This is the string of the responseServer.Data: ", dataRes)
	err10 := write(responseServer.Data, client)
	if err10 != nil {
		logger.Error("Write error failed for online register action: ", err10.Error())
		return errors.New(ServerInternalError), CommonResponse{}
	}
	res := GetFileRes(GB)
	if ! res.Value {
		logger.Error("This file is invalid")
		if err4 := RemoveFile(FilePath); err4 != nil {
			logger.Error("Failed to handle the invalid file")
		}
		//This is a rollback logic, need clear the license data in db also.
		if err := GB.RollbackContent(client.ClientID); err != nil {
			return err, CommonResponse{}
		}
	}

	return nil, responseServer
}

func PingCall() string {
	x := "chaoshenis here"
	return x
}

func (GB *GormDB)VerifyCall() CheckRes {
	res := GetFileRes(GB)
	logger.Info("This is the res in Verify: ", res)
	res.RegularCheck = GB.CheckResInDB()
	res.GetResTime = GetCurrentTime()
    return res
}

//for offline, generate the client id for the offline register
func (GB *GormDB)GenClientIDCall() (error, CommonResponse) {

/*	if ! VerifySN(sn.SN) {
		logger.Info("The SN is invalid")
		return errors.New(ClientRequestError), CommonResponse{}
	}*/
	ClientID := GenRcodeOffline()
	response := CommonResponse{
		Data: ClientID,
	}
    return nil, response
}

//Interface: Delete the license file
func RemoveCall() error {
	isThere, err := PathExists(FilePath)
	if err != nil {
		return err
	}

	if ! isThere {
		logger.Info("The file not exist, no need delete again")
		return errors.New("file not exist error")
	}

	if err := RemoveFile(FilePath); err != nil {
		logger.Error("Remove file error: ", err.Error())
		return err
	}
	return nil
}

//for deactivate the license for online and offline scene
//this interface will clear all the local data about license
//will execute 2 action: clear the local table, remove the license file
func (GB *GormDB)DeactivateService() error {
	logger.Info("Begin to deactivate Service")
	if err := GB.ClearTable(); err != nil {
		logger.Error("Clear the data in DB failed: ", err.Error())
		return err
	}
	if err2 := RemoveFile(FilePath); err2 != nil {
		logger.Error("Failed to handle the file, deactivated partially, please check the backend and finish it manually")
		return err2
	}
    logger.Info("End to deactivate Service")
	return nil
}

//for check the register status and client service status
func (GB *GormDB)GetRegisterInfo(hashString string) RegisterInfo {
	logger.Info("Begin to Get register Info from local site.")
	faultInfo := RegisterInfo{
		Status: "Deactivated",
	}
	err, data := GB.ReadAndDecryptFile(FilePath)
	if err != nil {
		logger.Error("Return deactivated because read file failed error: ", err.Error())
		return faultInfo
	}
	normalInfo := RegisterInfo{
		SN: data.SeriesNumber,
		HardwareID: data.ClusterCode,
		Plan: data.HashList[hashString],
		ExpiredTime: data.ExpiredTime,
	}
	logger.Info("End to Get register Info from local site.")
	return normalInfo
}
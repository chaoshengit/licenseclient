package licenseclient

import (
	"github.com/wonderivan/logger"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	"errors"
)

type GormDB struct {
	PgClient *gorm.DB
}

//update the idb,idc(last)
func (GB *GormDB) insertCtoDB(ids IdInfo) (err error) {
    if err = GB.PgClient.Create(ids).Error; err != nil {
    	return
	}
	return
}

func (GB *GormDB) updateC(timeString string) (error) {
	var id IdInfo
	var count int64
	if err1 := GB.PgClient.Table("id_infos").Where("used = ?",true).Count(&count).Error;err1 != nil {
		logger.Info("check the count failed")
		return err1
	}
	if count < 1 {
		return errors.New("no record found error")
	}
	if err := GB.PgClient.First(&id, "used = ?", true).Error; err != nil {
		logger.Error("This is the error when update the id infos1: ", err.Error())
		return err
	}

    tx := GB.PgClient.Begin()
	if err := tx.Model(IdInfo{}).Where("id_a = ?", id.IdA).Update("id_b", id.IdC).Error; err != nil {
		logger.Error("This is the error when update the id infos2: ", err.Error())
		tx.Rollback()
	    return err
	}
	if err2 := tx.Model(IdInfo{}).Where("id_a = ?", id.IdA).Update("id_c", timeString).Error; err2 != nil{
		logger.Error("This is the error when update the id infos3: ", err2.Error())
		tx.Rollback()
	    return err2
	}
	if err := tx.Commit().Error; err != nil {
		logger.Error("This is the error when update the id infos4: ", err.Error())
		tx.Rollback()
		return err
	}
	
	return nil
}

func (GB *GormDB) updateResult(result, ida string) (err error) {
    if err = GB.PgClient.Model(IdInfo{}).Where("id_a = ?", ida).Update("id_r",result).Error; err != nil {
    	return
	}
    return
}

func (GB *GormDB) CheckC() (checkRes bool) {
	var count int64
	if err := GB.PgClient.Table("id_infos").Where("used = ?",true).Count(&count).Error;err != nil {
		logger.Error("check the count failed")
		return false
	}
    if count > 0 {
    	return true
	}
	logger.Error("The count is 0, please check whether completed the register")
	return false
}

func (GB *GormDB) GetCids() (err error, ids []string) {
	if err = GB.PgClient.Model(IdInfo{}).Pluck("id_a", &ids).Error; err != nil {
		return
	}
	return
}

func (GB *GormDB) GetCRecord() (err error, record IdInfo) {
	if err = GB.PgClient.Where("used = true").First(&record).Error; err != nil {
		return
	}
	return
}

//clear all the data in table
func (GB *GormDB) ClearTable() (err error) {
	if err = GB.PgClient.Delete(IdInfo{}).Error; err != nil {
		return
	}
	return
}

//update the using status of the current license
func (GB *GormDB) UpdateUseState(client string) (error) {

	tx := GB.PgClient.Begin()
	if err := tx.Model(IdInfo{}).Where("used = true").Update("used", "f").Error; err != nil {
	    tx.Rollback()
	    return err
	}
    if err := tx.Model(IdInfo{}).Where("id_a = ? and used = false", client).Update("used", "t").Error; err != nil {
        tx.Rollback()
        return err
    }
    if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		return err
	}
    return nil
}

//update the license content when online register or upload the license file in offline scene
func (GB *GormDB) UpdateContent(client, content, sig string) (error) {
    tx := GB.PgClient.Begin()
	if err := tx.Model(IdInfo{}).Where("used = true").Update("used", "f").Error; err != nil {
	    tx.Rollback()
	    return err
	}
	if err := tx.Model(IdInfo{}).Where("id_a = ?", client).Update("content", content).Update("sig", sig).Update("used", "t").Error; err != nil {
	    tx.Rollback()
		return err
	}
	if err := tx.Commit().Error; err != nil {
		tx.Rollback()
		return err
	}
	return nil
}

func (GB *GormDB) RollbackContent(client string) (error) {
	if err := GB.PgClient.Model(IdInfo{}).Where("id_a = ?", client).Update("content", BlankString).Update("sig", BlankString).Update("used", "f").Error; err != nil {
		logger.Error("Rollback the content failed")
		return err
	}
	return nil
}
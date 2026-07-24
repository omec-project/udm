// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package producer

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	udm_context "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/logger"
	"github.com/omec-project/util/httpwrapper"
)

const (
	anyUE            = "anyUE"
	prefixMsisdn     = "msisdn-"
	prefixExtID      = "extid-"
	prefixExtgroupID = "extgroupid-"
	fmtPatchItem     = "patch item: %+v"
)

func HandleCreateEeSubscription(request *httpwrapper.Request) *httpwrapper.Response {
	logger.EeLog.Infoln("Handle Create EE Subscription")

	eesubscription := request.Body.(models.EeSubscription)
	ueIdentity := request.Params["ueIdentity"]

	createdEESubscription, problemDetails := CreateEeSubscriptionProcedure(ueIdentity, eesubscription)
	if createdEESubscription != nil {
		return httpwrapper.NewResponse(http.StatusCreated, nil, createdEESubscription)
	} else if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	} else {
		problemDetails = utils.ProblemDetailsWithCause("Unspecified NF failure", http.StatusInternalServerError, "", utils.CauseUnspecifiedNfFailure)
		return httpwrapper.NewResponse(http.StatusInternalServerError, nil, problemDetails)
	}
}

// TODO: complete this procedure based on TS 29503 5.5
func CreateEeSubscriptionProcedure(ueIdentity string,
	eesubscription models.EeSubscription,
) (*models.CreatedEeSubscription, *models.ProblemDetails) {
	udmSelf := udm_context.UDM_Self()

	logger.EeLog.Debugf("udIdentity: %s", ueIdentity)
	switch {
	// GPSI (MSISDN identifier) represents a single UE
	case strings.HasPrefix(ueIdentity, prefixMsisdn):
		fallthrough
	// GPSI (External identifier) represents a single UE
	case strings.HasPrefix(ueIdentity, prefixExtID):
		if ue, ok := udmSelf.UdmUeFindByGpsi(ueIdentity); ok {
			id, err := udmSelf.EeSubscriptionIDGenerator.Allocate()
			if err != nil {
				return nil, utils.ProblemDetailsWithCause("Unspecified NF failure", http.StatusInternalServerError, "", utils.CauseUnspecifiedNfFailure)
			}

			subscriptionID := strconv.Itoa(int(id))
			ue.StoreEeSubscription(subscriptionID, &eesubscription)
			createdEeSubscription := models.NewCreatedEeSubscription(eesubscription)
			return createdEeSubscription, nil
		} else {
			return nil, utils.ProblemDetailsUserNotFound()
		}
	// external groupID represents a group of UEs
	case strings.HasPrefix(ueIdentity, prefixExtgroupID):
		id, err := udmSelf.EeSubscriptionIDGenerator.Allocate()
		if err != nil {
			return nil, utils.ProblemDetailsWithCause("Unspecified NF failure", http.StatusInternalServerError, "", utils.CauseUnspecifiedNfFailure)
		}
		subscriptionID := strconv.Itoa(int(id))
		createdEeSubscription := models.NewCreatedEeSubscription(eesubscription)

		udmSelf.UdmUePool.Range(func(key, value interface{}) bool {
			ue := value.(*udm_context.UdmUeContext)
			if ue.ExternalGroupID == ueIdentity {
				ue.StoreEeSubscription(subscriptionID, &eesubscription)
			}
			return true
		})
		return createdEeSubscription, nil
	// represents any UEs
	case ueIdentity == anyUE:
		id, err := udmSelf.EeSubscriptionIDGenerator.Allocate()
		if err != nil {
			return nil, utils.ProblemDetailsWithCause("Unspecified NF failure", http.StatusInternalServerError, "", utils.CauseUnspecifiedNfFailure)
		}
		subscriptionID := strconv.Itoa(int(id))
		createdEeSubscription := models.NewCreatedEeSubscription(eesubscription)
		udmSelf.UdmUePool.Range(func(key, value interface{}) bool {
			ue := value.(*udm_context.UdmUeContext)
			ue.StoreEeSubscription(subscriptionID, &eesubscription)
			return true
		})
		return createdEeSubscription, nil
	default:
		problemDetails := utils.ProblemDetailsMandatoryIeIncorrect("")
		invalidParam := models.NewInvalidParam("ueIdentity")
		invalidParam.SetReason("incorrect format")
		problemDetails.SetInvalidParams([]models.InvalidParam{*invalidParam})
		return nil, problemDetails
	}
}

func HandleDeleteEeSubscription(request *httpwrapper.Request) *httpwrapper.Response {
	ueIdentity := request.Params["ueIdentity"]
	subscriptionID := request.Params["subscriptionID"]

	DeleteEeSubscriptionProcedure(ueIdentity, subscriptionID)
	return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
}

// TODO: complete this procedure based on TS 29503 5.5
func DeleteEeSubscriptionProcedure(ueIdentity string, subscriptionID string) {
	udmSelf := udm_context.UDM_Self()

	switch {
	case strings.HasPrefix(ueIdentity, prefixMsisdn):
		fallthrough
	case strings.HasPrefix(ueIdentity, prefixExtID):
		if ue, ok := udmSelf.UdmUeFindByGpsi(ueIdentity); ok {
			ue.DeleteEeSubscription(subscriptionID)
		}
	case strings.HasPrefix(ueIdentity, prefixExtgroupID):
		udmSelf.UdmUePool.Range(func(key, value interface{}) bool {
			ue := value.(*udm_context.UdmUeContext)
			if ue.ExternalGroupID == ueIdentity {
				ue.DeleteEeSubscription(subscriptionID)
			}
			return true
		})
	case ueIdentity == anyUE:
		udmSelf.UdmUePool.Range(func(key, value interface{}) bool {
			ue := value.(*udm_context.UdmUeContext)
			ue.DeleteEeSubscription(subscriptionID)
			return true
		})
	}
	if id, err := strconv.ParseInt(subscriptionID, 10, 64); err != nil {
		logger.EeLog.Warnf("subscriptionID covert type error: %+v", err)
	} else {
		udmSelf.EeSubscriptionIDGenerator.FreeID(id)
	}
}

func HandleUpdateEeSubscription(request *httpwrapper.Request) *httpwrapper.Response {
	logger.EeLog.Infoln("Handle Update EE subscription")
	logger.EeLog.Warnln("Update EE Subscription is not implemented")

	patchList := request.Body.([]models.PatchItem)
	ueIdentity := request.Params["ueIdentity"]
	subscriptionID := request.Params["subscriptionID"]

	problemDetails := UpdateEeSubscriptionProcedure(ueIdentity, subscriptionID, patchList)
	if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	} else {
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
}

// TODO: complete this procedure based on TS 29503 5.5
// applyPatchToUe localizes the patching logic and reduces nesting in the main caller.
func applyPatchToUe(ue *udm_context.UdmUeContext, subscriptionID string, patchList []models.PatchItem) bool {
	// Defensive check to prevent nil pointer dereference panics
	if ue == nil {
		return false
	}
	if !ue.HasEeSubscription(subscriptionID) {
		return false
	}
	for _, patchItem := range patchList {
		logger.EeLog.Debugf(fmtPatchItem, patchItem)
		// TODO: patch the Eesubscription
	}
	return true
}

func UpdateEeSubscriptionProcedure(ueIdentity string, subscriptionID string,
	patchList []models.PatchItem,
) *models.ProblemDetails {
	udmSelf := udm_context.UDM_Self()

	switch {
	case strings.HasPrefix(ueIdentity, prefixMsisdn), strings.HasPrefix(ueIdentity, prefixExtID):
		ue, ok := udmSelf.UdmUeFindByGpsi(ueIdentity)
		if !ok || !applyPatchToUe(ue, subscriptionID, patchList) {
			return utils.ProblemDetailsWithCause("Subscription not found", http.StatusNotFound, "", utils.CauseSubscriptionNotFound)
		}
		return nil
	case strings.HasPrefix(ueIdentity, prefixExtgroupID):
		udmSelf.UdmUePool.Range(func(key, value interface{}) bool {
			ue := value.(*udm_context.UdmUeContext)
			if ue.ExternalGroupID == ueIdentity {
				applyPatchToUe(ue, subscriptionID, patchList)
			}
			return true
		})
		return nil
	case ueIdentity == anyUE:
		udmSelf.UdmUePool.Range(func(key, value interface{}) bool {
			applyPatchToUe(value.(*udm_context.UdmUeContext), subscriptionID, patchList)
			return true
		})
		return nil
	default:
		problemDetails := utils.ProblemDetailsMandatoryIeIncorrect("")
		invalidParam := models.NewInvalidParam("ueIdentity")
		invalidParam.SetReason("incorrect format")
		problemDetails.SetInvalidParams([]models.InvalidParam{*invalidParam})
		return problemDetails
	}
}

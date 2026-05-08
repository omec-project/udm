// SPDX-FileCopyrightText: 2025 Intel Corporation
// Copyright 2019 free5GC.org
//
// SPDX-License-Identifier: Apache-2.0
//

package producer

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"reflect"
	"strings"

	"github.com/omec-project/openapi/v2"
	"github.com/omec-project/openapi/v2/models"
	"github.com/omec-project/openapi/v2/utils"
	udm_context "github.com/omec-project/udm/context"
	"github.com/omec-project/udm/logger"
	stats "github.com/omec-project/udm/metrics"
	"github.com/omec-project/udm/suci"
	"github.com/omec-project/util/httpwrapper"
	"github.com/omec-project/util/milenage"
	"github.com/omec-project/util/ueauth"
)

const (
	SqnMAx    int64 = 0xFFFFFFFFFFFF
	ind       int64 = 32
	keyStrLen int   = 32
	opStrLen  int   = 32
	opcStrLen int   = 32
)

const (
	authenticationRejected string = "AUTHENTICATION_REJECTED"
)

func aucSQN(opc, k, auts, rand []byte) ([]byte, []byte) {
	AK, SQNms := make([]byte, 6), make([]byte, 6)
	macS := make([]byte, 8)
	ConcSQNms := auts[:6]
	AMF, err := hex.DecodeString("0000")
	if err != nil {
		return nil, nil
	}

	logger.UeauLog.Debugln("ConcSQNms", ConcSQNms)

	err = milenage.F2345(opc, k, rand, nil, nil, nil, nil, AK)
	if err != nil {
		logger.UeauLog.Errorln("milenage F2345 err ", err)
	}

	for i := 0; i < 6; i++ {
		SQNms[i] = AK[i] ^ ConcSQNms[i]
	}

	err = milenage.F1(opc, k, rand, SQNms, AMF, nil, macS)
	if err != nil {
		logger.UeauLog.Errorln("milenage F1 err", err)
	}

	logger.UeauLog.Debugln("SQNms", SQNms)
	logger.UeauLog.Debugln("macS", macS)
	return SQNms, macS
}

func strictHex(s string, n int) string {
	l := len(s)
	if l < n {
		return fmt.Sprint(strings.Repeat("0", n-l) + s)
	} else {
		return s[l-n : l]
	}
}

func HandleGenerateAuthDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.UeauLog.Infoln("handle GenerateAuthDataRequest")
	authInfoRequest := request.Body.(models.AuthenticationInfoRequest)
	supiOrSuci := request.Params["supiOrSuci"]
	response, problemDetails := GenerateAuthDataProcedure(authInfoRequest, supiOrSuci)
	if response != nil {
		stats.IncrementUdmUeAuthenticationStats("create", "SUCCESS")
		// status code is based on SPEC, and option headers
		return httpwrapper.NewResponse(http.StatusOK, nil, response)
	} else if problemDetails != nil {
		stats.IncrementUdmUeAuthenticationStats("create", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	}
	problemDetails = utils.ProblemDetailsUnspecified()
	stats.IncrementUdmUeAuthenticationStats("create", "FAILURE")
	return httpwrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

func HandleConfirmAuthDataRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.UeauLog.Infoln("Handle ConfirmAuthDataRequest")

	authEvent := request.Body.(models.AuthEvent)
	supi := request.Params["supi"]

	problemDetails := ConfirmAuthDataProcedure(authEvent, supi)

	if problemDetails != nil {
		stats.IncrementUdmUeAuthenticationStats("create", "FAILURE")
		return httpwrapper.NewResponse(int(problemDetails.GetStatus()), nil, problemDetails)
	} else {
		stats.IncrementUdmUeAuthenticationStats("create", "SUCCESS")
		return httpwrapper.NewResponse(http.StatusCreated, nil, nil)
	}
}

func ConfirmAuthDataProcedure(authEvent models.AuthEvent, supi string) (problemDetails *models.ProblemDetails) {
	client, err := createUDMClientToUDR(supi)
	if err != nil {
		return utils.ProblemDetailsSystemFailure(err.Error())
	}
	apiCreateAuthenticationStatusRequest := client.AuthenticationStatusDocumentAPI.CreateAuthenticationStatus(
		context.Background(), supi)
	apiCreateAuthenticationStatusRequest = apiCreateAuthenticationStatusRequest.AuthEvent(authEvent)
	resp, err := client.AuthenticationStatusDocumentAPI.CreateAuthenticationStatusExecute(apiCreateAuthenticationStatusRequest)
	if err != nil {
		cause := err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(int32(resp.StatusCode))
		problemDetails.SetCause(*cause)
		problemDetails.SetDetail(err.Error())
		logger.UeauLog.Errorln("[ConfirmAuth]", err.Error())
		return problemDetails
	}
	defer func() {
		if rspCloseErr := resp.Body.Close(); rspCloseErr != nil {
			logger.UeauLog.Errorf("CreateAuthenticationStatus response body cannot close: %+v", rspCloseErr)
		}
	}()

	return nil
}

func GenerateAuthDataProcedure(authInfoRequest models.AuthenticationInfoRequest, supiOrSuci string) (
	response *models.AuthenticationInfoResult, problemDetails *models.ProblemDetails,
) {
	logger.UeauLog.Debugln("in GenerateAuthDataProcedure")

	response = &models.AuthenticationInfoResult{}
	supi, err := suci.ToSupi(supiOrSuci, udm_context.UDM_Self().SuciProfiles)
	if err != nil {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusForbidden)
		problemDetails.SetCause(authenticationRejected)
		problemDetails.SetDetail(err.Error())
		logger.UeauLog.Errorln("suciToSupi error:", err.Error())
		return nil, problemDetails
	}

	logger.UeauLog.Debugf("supi conversion => %s", supi)

	client, err := createUDMClientToUDR(supi)
	if err != nil {
		return nil, utils.ProblemDetailsSystemFailure(err.Error())
	}
	apiQueryAuthSubsDataRequest := client.AuthenticationDataDocumentAPI.QueryAuthSubsData(context.Background(), supi)
	authSubs, res, err := client.AuthenticationDataDocumentAPI.QueryAuthSubsDataExecute(apiQueryAuthSubsDataRequest)
	if err != nil {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusForbidden)
		problemDetails.SetCause(authenticationRejected)
		problemDetails.SetDetail(err.Error())
		if res != nil {
			logger.UeauLog.Errorf("return from UDR QueryAuthSubsData error: status=%s err=%v", res.Status, err)
		} else {
			logger.UeauLog.Errorf("return from UDR QueryAuthSubsData error: err=%v", err)
		}
		return nil, problemDetails
	}
	defer func() {
		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("QueryAuthSubsData response body cannot close: %+v", rspCloseErr)
		}
	}()

	/*
		K, RAND, CK, IK: 128 bits (16 bytes) (hex len = 32)
		SQN, AK: 48 bits (6 bytes) (hex len = 12) TS33.102 - 6.3.2
		AMF: 16 bits (2 bytes) (hex len = 4) TS33.102 - Annex H
	*/

	hasK, hasOP, hasOPC := false, false, false

	var kStr, opcStr string

	k, op, opc := make([]byte, 16), make([]byte, 16), make([]byte, 16)

	logger.UeauLog.Debugln("K", k)

	if authSubs.EncPermanentKey != nil {
		kStr = authSubs.GetEncPermanentKey()
		if len(kStr) == keyStrLen {
			k, err = hex.DecodeString(kStr)
			if err != nil {
				logger.UeauLog.Errorln("err", err)
			} else {
				hasK = true
			}
		} else {
			problemDetails = models.NewProblemDetails()
			problemDetails.SetStatus(http.StatusForbidden)
			problemDetails.SetCause(authenticationRejected)
			logger.UeauLog.Errorln("kStr length is", len(kStr))
			return nil, problemDetails
		}
	} else {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusForbidden)
		problemDetails.SetCause(authenticationRejected)
		logger.UeauLog.Errorln("Nil PermanentKey")
		return nil, problemDetails
	}

	if authSubs.EncOpcKey != nil && authSubs.GetEncOpcKey() != "" {
		opcStr = authSubs.GetEncOpcKey()
		if len(opcStr) == opcStrLen {
			opc, err = hex.DecodeString(opcStr)
			if err != nil {
				logger.UeauLog.Errorln("err", err)
			} else {
				hasOPC = true
			}
		} else {
			logger.UeauLog.Errorln("opcStr length is", len(opcStr))
		}
	} else {
		logger.UeauLog.Infoln("Nil Opc")
	}

	if !hasOPC && !hasOP {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusForbidden)
		problemDetails.SetCause(authenticationRejected)
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusForbidden)
		problemDetails.SetCause(authenticationRejected)
		problemDetails.SetDetail(err.Error())
		return nil, problemDetails
	}

	if !hasOPC {
		if hasK && hasOP {
			opc, err = milenage.GenerateOPC(k, op)
			if err != nil {
				logger.UeauLog.Errorln("milenage GenerateOPC err", err)
			}
		} else {
			problemDetails = models.NewProblemDetails()
			problemDetails.SetStatus(http.StatusForbidden)
			problemDetails.SetCause(authenticationRejected)
			logger.UeauLog.Errorln("unable to derive OPC")
			return nil, problemDetails
		}
	}

	sqnStr := strictHex(authSubs.SequenceNumber.GetSqn(), 12)
	logger.UeauLog.Debugln("sqnStr", sqnStr)
	sqn, err := hex.DecodeString(sqnStr)
	if err != nil {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusForbidden)
		problemDetails.SetCause(authenticationRejected)
		problemDetails.SetDetail(err.Error())
		logger.UeauLog.Errorln("err", err)
		return nil, problemDetails
	}

	logger.UeauLog.Debugln("sqn", sqn)

	RAND := make([]byte, 16)
	_, err = rand.Read(RAND)
	if err != nil {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusForbidden)
		problemDetails.SetCause(authenticationRejected)
		problemDetails.SetDetail(err.Error())
		logger.UeauLog.Errorln("err", err)
		return nil, problemDetails
	}

	AMF, err := hex.DecodeString("8000")
	if err != nil {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusForbidden)
		problemDetails.SetCause(authenticationRejected)
		problemDetails.SetDetail(err.Error())
		logger.UeauLog.Errorln("err", err)
		return nil, problemDetails
	}

	// re-synchroniztion
	if authInfoRequest.ResynchronizationInfo != nil {
		Auts, deCodeErr := hex.DecodeString(authInfoRequest.ResynchronizationInfo.Auts)
		if deCodeErr != nil {
			problemDetails = models.NewProblemDetails()
			problemDetails.SetStatus(http.StatusForbidden)
			problemDetails.SetCause(authenticationRejected)
			problemDetails.SetDetail(deCodeErr.Error())
			logger.UeauLog.Errorln("err", deCodeErr)
			return nil, problemDetails
		}

		randHex, deCodeErr := hex.DecodeString(authInfoRequest.ResynchronizationInfo.Rand)
		if deCodeErr != nil {
			problemDetails = models.NewProblemDetails()
			problemDetails.SetStatus(http.StatusForbidden)
			problemDetails.SetCause(authenticationRejected)
			problemDetails.SetDetail(deCodeErr.Error())
			logger.UeauLog.Errorln("err", deCodeErr)
			return nil, problemDetails
		}

		SQNms, macS := aucSQN(opc, k, Auts, randHex)
		if reflect.DeepEqual(macS, Auts[6:]) {
			_, err = rand.Read(RAND)
			if err != nil {
				problemDetails = models.NewProblemDetails()
				problemDetails.SetStatus(http.StatusForbidden)
				problemDetails.SetCause(authenticationRejected)
				problemDetails.SetDetail(err.Error())
				logger.UeauLog.Errorln("err", err)
				return nil, problemDetails
			}

			// increment sqn authSubs.SequenceNumber
			bigSQN := big.NewInt(0)
			sqnStr = hex.EncodeToString(SQNms)
			logger.UeauLog.Infof("SQNstr %s", sqnStr)
			bigSQN.SetString(sqnStr, 16)

			bigInc := big.NewInt(ind + 1)

			bigP := big.NewInt(SqnMAx)
			bigSQN = bigInc.Add(bigSQN, bigInc)
			bigSQN = bigSQN.Mod(bigSQN, bigP)
			sqnStr = fmt.Sprintf("%x", bigSQN)
			sqnStr = strictHex(sqnStr, 12)
		} else {
			logger.UeauLog.Errorln("Re-Sync MAC failed", supi)
			logger.UeauLog.Errorln("MACS", macS)
			logger.UeauLog.Errorln("Auts[6:]", Auts[6:])
			logger.UeauLog.Errorln("Sqn", SQNms)
			problemDetails = models.NewProblemDetails()
			problemDetails.SetStatus(http.StatusForbidden)
			problemDetails.SetCause("modification is rejected")
			return nil, problemDetails
		}
	}

	// increment sqn
	bigSQN := big.NewInt(0)
	sqn, err = hex.DecodeString(sqnStr)
	if err != nil {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusForbidden)
		problemDetails.SetCause(authenticationRejected)
		problemDetails.SetDetail(err.Error())
		logger.UeauLog.Errorln("err", err)
		return nil, problemDetails
	}

	bigSQN.SetString(sqnStr, 16)

	bigInc := big.NewInt(1)
	bigSQN = bigInc.Add(bigSQN, bigInc)

	SQNheStr := fmt.Sprintf("%x", bigSQN)
	SQNheStr = strictHex(SQNheStr, 12)
	patchItemArray := []models.PatchItem{
		{
			Op:    models.PATCHOPERATION_REPLACE,
			Path:  "/sequenceNumber/sqn",
			Value: SQNheStr,
		},
	}

	var rsp *http.Response
	apiModifyAuthenticationSubscriptionRequest := client.AuthenticationSubscriptionDocumentAPI.ModifyAuthenticationSubscription(
		context.Background(), supi)
	apiModifyAuthenticationSubscriptionRequest = apiModifyAuthenticationSubscriptionRequest.PatchItem(patchItemArray)
	_, rsp, err = client.AuthenticationSubscriptionDocumentAPI.ModifyAuthenticationSubscriptionExecute(apiModifyAuthenticationSubscriptionRequest)
	if err != nil {
		problemDetails = models.NewProblemDetails()
		problemDetails.SetStatus(http.StatusForbidden)
		problemDetails.SetCause("modification is rejected")
		problemDetails.SetDetail(err.Error())
		logger.UeauLog.Errorln("update sqn error", err)
		return nil, problemDetails
	}
	defer func() {
		if rspCloseErr := rsp.Body.Close(); rspCloseErr != nil {
			logger.SdmLog.Errorf("ModifyAuthentication response body cannot close: %+v", rspCloseErr)
		}
	}()

	// Run milenage
	macA, macS := make([]byte, 8), make([]byte, 8)
	CK, IK := make([]byte, 16), make([]byte, 16)
	RES := make([]byte, 8)
	AK, AKstar := make([]byte, 6), make([]byte, 6)

	// Generate macA, macS
	err = milenage.F1(opc, k, RAND, sqn, AMF, macA, macS)
	if err != nil {
		logger.UeauLog.Errorln("milenage F1 err ", err)
	}

	// Generate RES, CK, IK, AK, AKstar
	// RES == XRES (expected RES) for server
	err = milenage.F2345(opc, k, RAND, RES, CK, IK, AK, AKstar)
	if err != nil {
		logger.UeauLog.Errorln("milenage F2345 err", err)
	}

	// Generate AUTN
	SQNxorAK := make([]byte, 6)
	for i := 0; i < len(sqn); i++ {
		SQNxorAK[i] = sqn[i] ^ AK[i]
	}
	AUTN := append(append(SQNxorAK, AMF...), macA...)
	logger.UeauLog.Infof("AUTN = %x", AUTN)

	var av models.AuthenticationVector
	if authSubs.AuthenticationMethod == models.AUTHMETHOD__5_G_AKA {
		response.AuthType = models.AUTHTYPE__5_G_AKA
		av.Av5GHeAka = models.NewAv5GHeAka(models.AVTYPE__5_G_HE_AKA, "", "", "", "")

		// derive XRES*
		key := append(CK, IK...)
		FC := ueauth.FC_FOR_RES_STAR_XRES_STAR_DERIVATION
		P0 := []byte(authInfoRequest.ServingNetworkName)
		P1 := RAND
		P2 := RES

		kdfValForXresStar, err := ueauth.GetKDFValue(
			key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1), P2, ueauth.KDFLen(P2))
		if err != nil {
			logger.UeauLog.Error(err)
		}
		xresStar := kdfValForXresStar[len(kdfValForXresStar)/2:]

		// derive Kausf
		FC = ueauth.FC_FOR_KAUSF_DERIVATION
		P0 = []byte(authInfoRequest.ServingNetworkName)
		P1 = SQNxorAK
		kdfValForKausf, err := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1))
		if err != nil {
			logger.UeauLog.Error(err)
		}

		// Fill in rand, xresStar, autn, kausf
		av.Av5GHeAka.Rand = hex.EncodeToString(RAND)
		av.Av5GHeAka.XresStar = hex.EncodeToString(xresStar)
		av.Av5GHeAka.Autn = hex.EncodeToString(AUTN)
		av.Av5GHeAka.Kausf = hex.EncodeToString(kdfValForKausf)
	} else { // EAP-AKA'
		response.AuthType = models.AUTHTYPE_EAP_AKA_PRIME
		av.AvEapAkaPrime = models.NewAvEapAkaPrime(models.AVTYPE_EAP_AKA_PRIME, "", "", "", "", "")

		// derive CK' and IK'
		key := append(CK, IK...)
		FC := ueauth.FC_FOR_CK_PRIME_IK_PRIME_DERIVATION
		P0 := []byte(authInfoRequest.ServingNetworkName)
		P1 := SQNxorAK
		kdfVal, err := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1))
		if err != nil {
			logger.UeauLog.Error(err)
		}

		// For TS 35.208 test set 19 & RFC 5448 test vector 1
		// CK': 0093 962d 0dd8 4aa5 684b 045c 9edf fa04
		// IK': ccfc 230c a74f cc96 c0a5 d611 64f5 a76

		ckPrime := kdfVal[:len(kdfVal)/2]
		ikPrime := kdfVal[len(kdfVal)/2:]

		// Fill in rand, xres, autn, ckPrime, ikPrime
		av.AvEapAkaPrime.Rand = hex.EncodeToString(RAND)
		av.AvEapAkaPrime.Xres = hex.EncodeToString(RES)
		av.AvEapAkaPrime.Autn = hex.EncodeToString(AUTN)
		av.AvEapAkaPrime.CkPrime = hex.EncodeToString(ckPrime)
		av.AvEapAkaPrime.IkPrime = hex.EncodeToString(ikPrime)
	}

	response.SetAuthenticationVector(av)
	response.SetSupi(supi)
	return response, nil
}

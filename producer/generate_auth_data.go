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
		problemDetails = utils.ProblemDetailsFromOpenAPIError(resp, err)
		closeResponseBody(logger.UeauLog, resp, "CreateAuthenticationStatus")
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

func parseAuthKeys(authSubs *models.AuthenticationSubscription) (k, op, opc []byte, hasK, hasOP, hasOPC bool, problemDetails *models.ProblemDetails) {
	k, op, opc = make([]byte, 16), make([]byte, 16), make([]byte, 16)

	if authSubs.EncPermanentKey == nil {
		problemDetails = utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, "", utils.CauseAuthenticationRejected)
		logger.UeauLog.Errorln("Nil PermanentKey")
		return k, op, opc, hasK, hasOP, hasOPC, problemDetails
	}
	kStr := authSubs.GetEncPermanentKey()
	if len(kStr) != keyStrLen {
		problemDetails = utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, "", utils.CauseAuthenticationRejected)
		logger.UeauLog.Errorln("kStr length is", len(kStr))
		return k, op, opc, hasK, hasOP, hasOPC, problemDetails
	}
	var err error
	decodedK, err := hex.DecodeString(kStr)
	if err != nil || len(decodedK) != len(k) {
		problemDetails = utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, "Invalid permanent key encoding", utils.CauseAuthenticationRejected)
		logger.UeauLog.Errorln("permanent key decode error", err)
		return k, op, opc, hasK, hasOP, hasOPC, problemDetails
	}
	copy(k, decodedK)
	hasK = true
	var invalidOPCDetail string

	if authSubs.EncOpcKey != nil && authSubs.GetEncOpcKey() != "" {
		opcStr := authSubs.GetEncOpcKey()
		if len(opcStr) == opcStrLen {
			decodedOPC, decodeErr := hex.DecodeString(opcStr)
			if decodeErr != nil || len(decodedOPC) != len(opc) {
				invalidOPCDetail = "Invalid OPc encoding"
				logger.UeauLog.Errorln("opc decode error", decodeErr)
			} else {
				copy(opc, decodedOPC)
				hasOPC = true
			}
		} else {
			invalidOPCDetail = "Invalid OPc length"
			logger.UeauLog.Errorln("opcStr length is", len(opcStr))
		}
	} else {
		logger.UeauLog.Infoln("Nil Opc")
	}

	if !hasOPC {
		if authSubs.EncTopcKey != nil && authSubs.GetEncTopcKey() != "" {
			opStr := authSubs.GetEncTopcKey()
			if len(opStr) == opStrLen {
				decodedOP, decodeErr := hex.DecodeString(opStr)
				if decodeErr != nil || len(decodedOP) != len(op) {
					problemDetails = utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, "Invalid OP encoding", utils.CauseAuthenticationRejected)
					logger.UeauLog.Errorln("op decode error", decodeErr)
					return k, op, opc, hasK, hasOP, hasOPC, problemDetails
				}
				copy(op, decodedOP)
				hasOP = true
			} else {
				problemDetails = utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, "Invalid OP encoding", utils.CauseAuthenticationRejected)
				logger.UeauLog.Errorln("opStr length is", len(opStr))
				return k, op, opc, hasK, hasOP, hasOPC, problemDetails
			}
		} else {
			logger.UeauLog.Infoln("Nil Op")
		}
	}

	if !hasOPC && !hasOP {
		detail := "Both OP and OPc are missing"
		if invalidOPCDetail != "" {
			detail = invalidOPCDetail
		}
		problemDetails = utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, detail, utils.CauseAuthenticationRejected)
	}
	return k, op, opc, hasK, hasOP, hasOPC, problemDetails
}

func GenerateAuthDataProcedure(authInfoRequest models.AuthenticationInfoRequest, supiOrSuci string) (
	response *models.AuthenticationInfoResult, problemDetails *models.ProblemDetails,
) {
	logger.UeauLog.Debugln("in GenerateAuthDataProcedure")

	response = models.NewAuthenticationInfoResultWithDefaults()
	supi, err := suci.ToSupi(supiOrSuci, udm_context.UDM_Self().SuciProfiles)
	if err != nil {
		problemDetails = utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, err.Error(), utils.CauseAuthenticationRejected)
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
		problemDetails = utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, err.Error(), utils.CauseAuthenticationRejected)
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

	var (
		k, op, opc          []byte
		hasK, hasOP, hasOPC bool
	)
	k, op, opc, hasK, hasOP, hasOPC, problemDetails = parseAuthKeys(authSubs)
	if problemDetails != nil {
		return nil, problemDetails
	}

	if !hasOPC {
		if hasK && hasOP {
			opc, err = milenage.GenerateOPC(k, op)
			if err != nil {
				logger.UeauLog.Errorln("milenage GenerateOPC err", err)
			}
		} else {
			problemDetails = utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, "", utils.CauseAuthenticationRejected)
			logger.UeauLog.Errorln("unable to derive OPC")
			return nil, problemDetails
		}
	}

	sqnStr := strictHex(authSubs.SequenceNumber.GetSqn(), 12)
	logger.UeauLog.Debugln("sqnStr", sqnStr)
	sqn, err := hex.DecodeString(sqnStr)
	if err != nil {
		problemDetails = utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, err.Error(), utils.CauseAuthenticationRejected)
		logger.UeauLog.Errorln("err", err)
		return nil, problemDetails
	}

	logger.UeauLog.Debugln("sqn", sqn)

	RAND := make([]byte, 16)
	_, err = rand.Read(RAND)
	if err != nil {
		problemDetails = utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, err.Error(), utils.CauseAuthenticationRejected)
		logger.UeauLog.Errorln("err", err)
		return nil, problemDetails
	}

	AMF, err := hex.DecodeString("8000")
	if err != nil {
		problemDetails = utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, err.Error(), utils.CauseAuthenticationRejected)
		logger.UeauLog.Errorln("err", err)
		return nil, problemDetails
	}

	// re-synchroniztion
	if authInfoRequest.ResynchronizationInfo != nil {
		Auts, deCodeErr := hex.DecodeString(authInfoRequest.ResynchronizationInfo.Auts)
		if deCodeErr != nil {
			problemDetails = utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, deCodeErr.Error(), utils.CauseAuthenticationRejected)
			logger.UeauLog.Errorln("err", deCodeErr)
			return nil, problemDetails
		}

		randHex, deCodeErr := hex.DecodeString(authInfoRequest.ResynchronizationInfo.Rand)
		if deCodeErr != nil {
			problemDetails = utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, deCodeErr.Error(), utils.CauseAuthenticationRejected)
			logger.UeauLog.Errorln("err", deCodeErr)
			return nil, problemDetails
		}

		SQNms, macS := aucSQN(opc, k, Auts, randHex)
		if reflect.DeepEqual(macS, Auts[6:]) {
			_, err = rand.Read(RAND)
			if err != nil {
				problemDetails = utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, err.Error(), utils.CauseAuthenticationRejected)
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
			problemDetails = utils.ProblemDetailsWithCause("Modification rejected", http.StatusForbidden, "", utils.CauseModifyNotAllowed)
			return nil, problemDetails
		}
	}

	// increment sqn
	bigSQN := big.NewInt(0)
	sqn, err = hex.DecodeString(sqnStr)
	if err != nil {
		problemDetails = utils.ProblemDetailsWithCause("Authentication rejected", http.StatusForbidden, err.Error(), utils.CauseAuthenticationRejected)
		logger.UeauLog.Errorln("err", err)
		return nil, problemDetails
	}

	bigSQN.SetString(sqnStr, 16)

	bigInc := big.NewInt(1)
	bigSQN = bigInc.Add(bigSQN, bigInc)

	SQNheStr := fmt.Sprintf("%x", bigSQN)
	SQNheStr = strictHex(SQNheStr, 12)
	patchItem := models.NewPatchItem(models.PATCHOPERATION_REPLACE, "/sequenceNumber/sqn")
	patchItem.SetValue(SQNheStr)
	patchItemArray := []models.PatchItem{*patchItem}

	var rsp *http.Response
	apiModifyAuthenticationSubscriptionRequest := client.AuthenticationSubscriptionDocumentAPI.ModifyAuthenticationSubscription(
		context.Background(), supi)
	apiModifyAuthenticationSubscriptionRequest = apiModifyAuthenticationSubscriptionRequest.PatchItem(patchItemArray)
	_, rsp, err = client.AuthenticationSubscriptionDocumentAPI.ModifyAuthenticationSubscriptionExecute(apiModifyAuthenticationSubscriptionRequest)
	if err != nil {
		problemDetails = utils.ProblemDetailsWithCause("Modification rejected", http.StatusForbidden, err.Error(), utils.CauseModifyNotAllowed)
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
	if authSubs.GetAuthenticationMethod() == models.AUTHMETHOD__5_G_AKA {
		response.SetAuthType(models.AUTHTYPE__5_G_AKA)
		av5GHeAka := models.NewAv5GHeAka(models.AVTYPE__5_G_HE_AKA, "", "", "", "")

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
		av5GHeAka.SetRand(hex.EncodeToString(RAND))
		av5GHeAka.SetXresStar(hex.EncodeToString(xresStar))
		av5GHeAka.SetAutn(hex.EncodeToString(AUTN))
		av5GHeAka.SetKausf(hex.EncodeToString(kdfValForKausf))
		av = models.Av5GHeAkaAsAuthenticationVector(av5GHeAka)
	} else { // EAP-AKA'
		response.SetAuthType(models.AUTHTYPE_EAP_AKA_PRIME)

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
		avEapAkaPrime := models.NewAvEapAkaPrime(models.AVTYPE_EAP_AKA_PRIME, hex.EncodeToString(RAND), hex.EncodeToString(RES), hex.EncodeToString(AUTN), hex.EncodeToString(ckPrime), hex.EncodeToString(ikPrime))
		av = models.AvEapAkaPrimeAsAuthenticationVector(avEapAkaPrime)
	}

	response.SetAuthenticationVector(av)
	response.SetSupi(supi)
	return response, nil
}

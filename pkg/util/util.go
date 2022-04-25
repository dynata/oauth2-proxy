package util

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"

	corpus "github.com/dynata/proto-api/go/iam/corpus/v1"
)

type ClaimsTransformer func(map[string]interface{}) (map[string]interface{}, error)

func GetCertPool(paths []string) (*x509.CertPool, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("invalid empty list of Root CAs file paths")
	}
	pool := x509.NewCertPool()
	for _, path := range paths {
		// Cert paths are a configurable option
		data, err := ioutil.ReadFile(path) // #nosec G304
		if err != nil {
			return nil, fmt.Errorf("certificate authority file (%s) could not be read - %s", path, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("loading certificate authority (%s) failed", path)
		}
	}
	return pool, nil
}

func CreateClaimsTransformer(effCompID int64, corpusClientRoles map[string]*corpus.ClientRoles) (ClaimsTransformer, error) {

	const (
		rolesStr          = "roles"
		resourceAccessStr = "resource_access"
		effCompanyIdStr   = "effective_company_id"
	)
	return func(parsedClaims map[string]interface{}) (map[string]interface{}, error) {
		// start with new claims which override/set custom claims
		newClaims := map[string]interface{}{effCompanyIdStr: effCompID}
		if len(parsedClaims) == 0 {
			return newClaims, nil
		}
		raInterface, foundRA := parsedClaims[resourceAccessStr]
		if !foundRA {
			return newClaims, nil
		}
		raMap, ok := raInterface.(map[string]interface{})
		if !ok {
			// not sure what type of structure is at "resource_access" and we can't go through it so just
			// copy it over without modification.
			newClaims[resourceAccessStr] = raInterface
			return newClaims, nil
		}
		newRA := map[string]interface{}{}
		newClaims[resourceAccessStr] = newRA
		for raKey, raVal := range raMap {
			ccrs, foundInCCRs := corpusClientRoles[raKey]
			if !foundInCCRs {
				// we don't know about value. just copy it over.
				newRA[raKey] = raVal
				continue
			}
			raValMap, raValIsMap := raVal.(map[string]interface{})
			if !raValIsMap {
				// structure is not a map so we can't inspect it. just copy it over.
				newRA[raKey] = raVal
				continue
			}
			newRAValMap := map[string]interface{}{}
			newRA[raKey] = newRAValMap
			for raValKey, raValVal := range raValMap {
				if raValKey != rolesStr {
					newRAValMap[raValKey] = raValVal
					continue
				}
				raValRoles, raValRolesIsSlice := raValVal.([]interface{})
				if !raValRolesIsSlice {
					// roles is not a slice so we can't inspect it. just copy over.
					newRAValMap[raValKey] = raValVal
					continue
				}
				newRAValRoles := make([]interface{}, 0, len(raValRoles))
				for _, raValRoleInterface := range raValRoles {
					raValRole, raValRoleIsString := raValRoleInterface.(string)
					if !raValRoleIsString {
						// not a string so we can't inspect it. just copy over.
						newRAValRoles = append(newRAValRoles, raValRoleInterface)
						continue
					}
					var matchingCCR *corpus.ClientRole
					for _, ccr := range ccrs.ClientRoles {
						if ccr.Name == raValRole {
							matchingCCR = ccr
							break
						}
					}
					if matchingCCR == nil {
						// no match from corpus. just copy over.
						newRAValRoles = append(newRAValRoles, raValRoleInterface)
						continue
					}
					// if we are here then corpus client role matches and we need to check to
					// see if role should be included.
					if matchingCCR.AssignedForCompany {
						newRAValRoles = append(newRAValRoles, raValRoleInterface)
					}
				}
				if len(newRAValRoles) > 0 {
					// only add roles if there are some
					newRAValMap[rolesStr] = newRAValRoles
				}
			}

			if len(newRAValMap) == 0 {
				// remove entry if it's completely empty
				delete(newRA, raKey)
			}
		}

		return newClaims, nil
	}, nil
}

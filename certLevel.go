// Level of verification certificate: OV, DV, EV

package sct

import (
	"strings"

	"github.com/google/certificate-transparency-go/asn1"
	ctx509 "github.com/google/certificate-transparency-go/x509"
)


type CertValidationLevel int

const (
	UnknownValidationLevel CertValidationLevel = 0
	DV                     CertValidationLevel = 1
	OV                     CertValidationLevel = 2
	EV                     CertValidationLevel = 3
)

// TODO: All of validation-level maps should be auto-generated from
// https://github.com/zmap/constants.

// ExtendedValidationOIDs contains the UNION of Chromium
// (https://chromium.googlesource.com/chromium/src/net/+/master/cert/ev_root_ca_metadata.cc)
// and Firefox
// (http://hg.mozilla.org/mozilla-central/file/tip/security/certverifier/ExtendedValidation.cpp)
// EV OID lists
var ExtendedValidationOIDs = map[string]interface{}{
	// CA/Browser Forum EV OID standard
	// https://cabforum.org/object-registry/
	"2.23.140.1.1": nil,
	// CA/Browser Forum EV Code Signing
	"2.23.140.1.3": nil,
	// CA/Browser Forum .onion EV Certs
	"2.23.140.1.31": nil,
	// AC Camerfirma S.A. Chambers of Commerce Root - 2008
	// https://www.camerfirma.com
	// AC Camerfirma uses the last two arcs to track how the private key
	// is managed - the effective verification policy is the same.
	"1.3.6.1.4.1.17326.10.14.2.1.2": nil,
	"1.3.6.1.4.1.17326.10.14.2.2.2": nil,
	// AC Camerfirma S.A. Global Chambersign Root - 2008
	// https://server2.camerfirma.com:8082
	// AC Camerfirma uses the last two arcs to track how the private key
	// is managed - the effective verification policy is the same.
	"1.3.6.1.4.1.17326.10.8.12.1.2": nil,
	"1.3.6.1.4.1.17326.10.8.12.2.2": nil,
	// Actalis Authentication Root CA
	// https://ssltest-a.actalis.it:8443
	"1.3.159.1.17.1": nil,
	// AffirmTrust Commercial
	// https://commercial.affirmtrust.com/
	"1.3.6.1.4.1.34697.2.1": nil,
	// AffirmTrust Networking
	// https://networking.affirmtrust.com:4431
	"1.3.6.1.4.1.34697.2.2": nil,
	// AffirmTrust Premium
	// https://premium.affirmtrust.com:4432/
	"1.3.6.1.4.1.34697.2.3": nil,
	// AffirmTrust Premium ECC
	// https://premiumecc.affirmtrust.com:4433/
	"1.3.6.1.4.1.34697.2.4": nil,
	// Autoridad de Certificacion Firmaprofesional CIF A62634068
	// https://publifirma.firmaprofesional.com/
	"1.3.6.1.4.1.13177.10.1.3.10": nil,
	// Buypass Class 3 CA 1
	// https://valid.evident.ca13.ssl.buypass.no/
	"2.16.578.1.26.1.3.3": nil,
	// Certification Authority of WoSign
	// CA 沃通根证书
	// https://root2evtest.wosign.com/
	"1.3.6.1.4.1.36305.2": nil,
	// CertPlus Class 2 Primary CA (KEYNECTIS)
	// https://www.keynectis.com/
	"1.3.6.1.4.1.22234.2.5.2.3.1": nil,
	// Certum Trusted Network CA
	// https://juice.certum.pl/
	"1.2.616.1.113527.2.5.1.1": nil,
	// China Internet Network Information Center EV Certificates Root
	// https://evdemo.cnnic.cn/
	"1.3.6.1.4.1.29836.1.10": nil,
	// COMODO Certification Authority & USERTrust RSA Certification Authority & UTN-USERFirst-Hardware & AddTrust External CA Root
	// https://secure.comodo.com/
	// https://usertrustrsacertificationauthority-ev.comodoca.com/
	// https://addtrustexternalcaroot-ev.comodoca.com
	"1.3.6.1.4.1.6449.1.2.1.5.1": nil,
	// Cybertrust Global Root & GTE CyberTrust Global Root & Baltimore CyberTrust Root
	// https://evup.cybertrust.ne.jp/ctj-ev-upgrader/evseal.gif
	// https://www.cybertrust.ne.jp/
	// https://secure.omniroot.com/repository/
	"1.3.6.1.4.1.6334.1.100.1": nil,
	// DigiCert High Assurance EV Root CA
	// https://www.digicert.com
	"2.16.840.1.114412.2.1": nil,
	// D-TRUST Root Class 3 CA 2 EV 2009
	// https://certdemo-ev-valid.ssl.d-trust.net/
	"1.3.6.1.4.1.4788.2.202.1": nil,
	// Entrust.net Secure Server Certification Authority
	// https://www.entrust.net/
	"2.16.840.1.114028.10.1.2": nil,
	// E-Tugra Certification Authority
	// https://sslev.e-tugra.com.tr
	"2.16.792.3.0.4.1.1.4": nil,
	// GeoTrust Primary Certification Authority
	// https://www.geotrust.com/
	"1.3.6.1.4.1.14370.1.6": nil,
	// GlobalSign Root CA - R2
	// https://www.globalsign.com/
	"1.3.6.1.4.1.4146.1.1": nil,
	// Go Daddy Class 2 Certification Authority & Go Daddy Root Certificate Authority - G2
	// https://www.godaddy.com/
	// https://valid.gdig2.catest.godaddy.com/
	"2.16.840.1.114413.1.7.23.3": nil,
	// Izenpe.com - SHA256 root
	// The first OID is for businesses and the second for government entities.
	// These are the test sites, respectively:
	// https://servicios.izenpe.com
	// https://servicios1.izenpe.com
	// Windows XP finds this, SHA1, root instead. The policy OIDs are the same
	// as for the SHA256 root, above.
	"1.3.6.1.4.1.14777.6.1.1": nil,
	"1.3.6.1.4.1.14777.6.1.2": nil,
	// Network Solutions Certificate Authority
	// https://www.networksolutions.com/website-packages/index.jsp
	"1.3.6.1.4.1.782.1.2.1.8.1": nil,
	// QuoVadis Root CA 2
	// https://www.quovadis.bm/
	"1.3.6.1.4.1.8024.0.2.100.1.2": nil,
	// SecureTrust CA, SecureTrust Corporation
	// https://www.securetrust.com
	// https://www.trustwave.com/
	"2.16.840.1.114404.1.1.2.4.1": nil,
	// Security Communication RootCA1
	// https://www.secomtrust.net/contact/form.html
	"1.2.392.200091.100.721.1": nil,
	// Staat der Nederlanden EV Root CA
	// https://pkioevssl-v.quovadisglobal.com/
	"2.16.528.1.1003.1.2.7": nil,
	// StartCom Certification Authority
	// https://www.startssl.com/
	"1.3.6.1.4.1.23223.1.1.1": nil,
	// Starfield Class 2 Certification Authority
	// https://www.starfieldtech.com/
	"2.16.840.1.114414.1.7.23.3": nil,
	// Starfield Services Root Certificate Authority - G2
	// https://valid.sfsg2.catest.starfieldtech.com/
	"2.16.840.1.114414.1.7.24.3": nil,
	// SwissSign Gold CA - G2
	// https://testevg2.swisssign.net/
	"2.16.756.1.89.1.2.1.1": nil,
	// Swisscom Root EV CA 2
	// https://test-quarz-ev-ca-2.pre.swissdigicert.ch
	"2.16.756.1.83.21.0": nil,
	// thawte Primary Root CA
	// https://www.thawte.com/
	"2.16.840.1.113733.1.7.48.1": nil,
	// TWCA Global Root CA
	// https://evssldemo3.twca.com.tw/index.html
	"1.3.6.1.4.1.40869.1.1.22.3": nil,
	// T-TeleSec GlobalRoot Class 3
	// http://www.telesec.de/ / https://root-class3.test.telesec.de/
	"1.3.6.1.4.1.7879.13.24.1": nil,
	// VeriSign Class 3 Public Primary Certification Authority - G5
	// https://www.verisign.com/
	"2.16.840.1.113733.1.7.23.6": nil,
	// Wells Fargo WellsSecure Public Root Certificate Authority
	// https://nerys.wellsfargo.com/test.html
	"2.16.840.1.114171.500.9": nil,
	// CN=CFCA EV ROOT,O=China Financial Certification Authority,C=CN
	// https://www.cfca.com.cn/
	"2.16.156.112554.3": nil,
	// CN=OISTE WISeKey Global Root GB CA,OU=OISTE Foundation Endorsed,O=WISeKey,C=CH
	// https://www.wisekey.com/repository/cacertificates/
	"2.16.756.5.14.7.4.8": nil,
	// CN=TÜRKTRUST Elektronik Sertifika Hizmet Sağlayıcısı H6,O=TÜRKTRUST Bilgi İletişim ve Bilişim Güvenliği Hizmetleri A...,L=Ankara,C=TR
	// https://www.turktrust.com.tr/
	"2.16.792.3.0.3.1.1.5": nil,
}

// OrganizationValidationOIDs contains CA specific OV OIDs from
// https://cabforum.org/object-registry/
var OrganizationValidationOIDs = map[string]interface{}{
	// CA/Browser Forum OV OID standard
	// https://cabforum.org/object-registry/
	"2.23.140.1.2.2": nil,
	// CA/Browser Forum individually validated
	"2.23.140.1.2.3": nil,
	// Digicert
	"2.16.840.1.114412.1.1": nil,
	// D-Trust
	"1.3.6.1.4.1.4788.2.200.1": nil,
	// GoDaddy
	"2.16.840.1.114413.1.7.23.2": nil,
	// Logius
	"2.16.528.1.1003.1.2.5.6": nil,
	// QuoVadis
	"1.3.6.1.4.1.8024.0.2.100.1.1": nil,
	// Starfield
	"2.16.840.1.114414.1.7.23.2": nil,
	// TurkTrust
	"2.16.792.3.0.3.1.1.2": nil,
}

// DomainValidationOIDs contain OIDs that identify DV certs.
var DomainValidationOIDs = map[string]interface{}{
	// Globalsign
	"1.3.6.1.4.1.4146.1.10.10": nil,
	// Let's Encrypt
	"1.3.6.1.4.1.44947.1.1.1": nil,
	// Comodo (eNom)
	"1.3.6.1.4.1.6449.1.2.2.10": nil,
	// Comodo (WoTrust)
	"1.3.6.1.4.1.6449.1.2.2.15": nil,
	// Comodo (RBC SOFT)
	"1.3.6.1.4.1.6449.1.2.2.16": nil,
	// Comodo (RegisterFly)
	"1.3.6.1.4.1.6449.1.2.2.17": nil,
	// Comodo (Central Security Patrols)
	"1.3.6.1.4.1.6449.1.2.2.18": nil,
	// Comodo (eBiz Networks)
	"1.3.6.1.4.1.6449.1.2.2.19": nil,
	// Comodo (OptimumSSL)
	"1.3.6.1.4.1.6449.1.2.2.21": nil,
	// Comodo (WoSign)
	"1.3.6.1.4.1.6449.1.2.2.22": nil,
	// Comodo (Register.com)
	"1.3.6.1.4.1.6449.1.2.2.24": nil,
	// Comodo (The Code Project)
	"1.3.6.1.4.1.6449.1.2.2.25": nil,
	// Comodo (Gandi)
	"1.3.6.1.4.1.6449.1.2.2.26": nil,
	// Comodo (GlobeSSL)
	"1.3.6.1.4.1.6449.1.2.2.27": nil,
	// Comodo (DreamHost)
	"1.3.6.1.4.1.6449.1.2.2.28": nil,
	// Comodo (TERENA)
	"1.3.6.1.4.1.6449.1.2.2.29": nil,
	// Comodo (GlobalSSL)
	"1.3.6.1.4.1.6449.1.2.2.31": nil,
	// Comodo (IceWarp)
	"1.3.6.1.4.1.6449.1.2.2.35": nil,
	// Comodo (Dotname Korea)
	"1.3.6.1.4.1.6449.1.2.2.37": nil,
	// Comodo (TrustSign)
	"1.3.6.1.4.1.6449.1.2.2.38": nil,
	// Comodo (Formidable)
	"1.3.6.1.4.1.6449.1.2.2.39": nil,
	// Comodo (SSL Blindado)
	"1.3.6.1.4.1.6449.1.2.2.40": nil,
	// Comodo (Dreamscape Networks)
	"1.3.6.1.4.1.6449.1.2.2.41": nil,
	// Comodo (K Software)
	"1.3.6.1.4.1.6449.1.2.2.42": nil,
	// Comodo (FBS)
	"1.3.6.1.4.1.6449.1.2.2.44": nil,
	// Comodo (ReliaSite)
	"1.3.6.1.4.1.6449.1.2.2.45": nil,
	// Comodo (CertAssure)
	"1.3.6.1.4.1.6449.1.2.2.47": nil,
	// Comodo (TrustAsia)
	"1.3.6.1.4.1.6449.1.2.2.49": nil,
	// Comodo (SecureCore)
	"1.3.6.1.4.1.6449.1.2.2.50": nil,
	// Comodo (Western Digital)
	"1.3.6.1.4.1.6449.1.2.2.51": nil,
	// Comodo (cPanel)
	"1.3.6.1.4.1.6449.1.2.2.52": nil,
	// Comodo (BlackCert)
	"1.3.6.1.4.1.6449.1.2.2.53": nil,
	// Comodo (KeyNet Systems)
	"1.3.6.1.4.1.6449.1.2.2.54": nil,
	// Comodo
	"1.3.6.1.4.1.6449.1.2.2.7": nil,
	// Comodo (CSC)
	"1.3.6.1.4.1.6449.1.2.2.8": nil,
	// Digicert
	"2.16.840.1.114412.1.2": nil,
	// GoDaddy
	"2.16.840.1.114413.1.7.23.1": nil,
	// Starfield
	"2.16.840.1.114414.1.7.23.1": nil,
	// CA/B Forum
	"2.23.140.1.2.1": nil,
}

func ValidationLevel(out *ctx509.Certificate) string {
	// See http://unmitigatedrisk.com/?p=203
	validationLevel := getMaxCertValidationLevel(out.PolicyIdentifiers)
	if validationLevel == UnknownValidationLevel {
		if (len(out.Subject.Organization) > 0 && out.Subject.Organization[0] == out.Subject.CommonName) || (len(out.Subject.OrganizationalUnit) > 0 && strings.Contains(out.Subject.OrganizationalUnit[0], "Domain Control Validated")) {
			if len(out.Subject.Locality) == 0 && len(out.Subject.Province) == 0 && len(out.Subject.PostalCode) == 0 {
				validationLevel = DV
			}
		} else if len(out.Subject.Organization) > 0 && out.Subject.Organization[0] == "Persona Not Validated" && strings.Contains(out.Issuer.CommonName, "StartCom") {
			validationLevel = DV
		}
	}
	return validationLevel.String()
}

func getMaxCertValidationLevel(oids []asn1.ObjectIdentifier) CertValidationLevel {
	maxOID := UnknownValidationLevel
	for _, oid := range oids {
		if _, ok := ExtendedValidationOIDs[oid.String()]; ok {
			return EV
		} else if _, ok := OrganizationValidationOIDs[oid.String()]; ok {
			maxOID = maxValidationLevel(maxOID, OV)
		} else if _, ok := DomainValidationOIDs[oid.String()]; ok {
			maxOID = maxValidationLevel(maxOID, DV)
		}
	}
	return maxOID
}

func maxValidationLevel(a, b CertValidationLevel) CertValidationLevel {
	if a > b {
		return a
	}
	return b
}
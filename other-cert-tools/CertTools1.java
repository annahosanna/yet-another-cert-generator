package example;

/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

// package org.cesecore.util;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;
import org.apache.commons.lang.CharUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509DefaultEntryConverter;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509NameEntryConverter;
import org.bouncycastle.asn1.x509.X509NameTokenizer;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CVCAuthorizationTemplate;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.ReferenceField;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;

/**
 * Tools to handle common certificate operations.
 *
 * Based on EJBCA version: CertTools1.java 11281 2011-01-28 16:45:42Z anatom
 *
 * @version $Id$
 */
public class CertTools1 {

  private static final Logger log = Logger.getLogger(CertTools1.class);

  // Initialize dnComponents
  static {
    DnComponents.getDnObjects(true);
  }

  public static final String EMAIL = "rfc822name";
  public static final String EMAIL1 = "email";
  public static final String EMAIL2 = "EmailAddress";
  public static final String EMAIL3 = "E";
  public static final String DNS = "dNSName";
  public static final String URI = "uniformResourceIdentifier";
  public static final String URI1 = "uri";
  public static final String URI2 = "uniformResourceId";
  public static final String IPADDR = "iPAddress";
  public static final String DIRECTORYNAME = "directoryName";

  /** Kerberos altName for smart card logon */
  public static final String KRB5PRINCIPAL = "krb5principal";
  /** OID for Kerberos altName for smart card logon */
  public static final String KRB5PRINCIPAL_OBJECTID = "1.3.6.1.5.2.2";
  /** Microsoft altName for windows smart card logon */
  public static final String UPN = "upn";
  /** ObjectID for upn altName for windows smart card logon */
  public static final String UPN_OBJECTID = "1.3.6.1.4.1.311.20.2.3";
  /** Microsoft altName for windows domain controller guid */
  public static final String GUID = "guid";
  /** ObjectID for upn altName for windows domain controller guid */
  public static final String GUID_OBJECTID = "1.3.6.1.4.1.311.25.1";
  /** ObjectID for Microsoft Encrypted File System Certificates extended key usage */
  public static final String EFS_OBJECTID = "1.3.6.1.4.1.311.10.3.4";
  /** ObjectID for Microsoft Encrypted File System Recovery Certificates extended key usage */
  public static final String EFSR_OBJECTID = "1.3.6.1.4.1.311.10.3.4.1";
  /** ObjectID for Microsoft Signer of documents extended key usage */
  public static final String MS_DOCUMENT_SIGNING_OBJECTID =
    "1.3.6.1.4.1.311.10.3.12";
  /** Object id id-pkix */
  public static final String id_pkix = "1.3.6.1.5.5.7";
  /** Object id id-kp */
  public static final String id_kp = id_pkix + ".3";
  /** Object id id-pda */
  public static final String id_pda = id_pkix + ".9";
  /**
   * Object id id-pda-dateOfBirth DateOfBirth ::= GeneralizedTime
   */
  public static final String id_pda_dateOfBirth = id_pda + ".1";
  /**
   * Object id id-pda-placeOfBirth PlaceOfBirth ::= DirectoryString
   */
  public static final String id_pda_placeOfBirth = id_pda + ".2";
  /**
   * Object id id-pda-gender Gender ::= PrintableString (SIZE(1)) -- "M", "F", "m" or "f"
   */
  public static final String id_pda_gender = id_pda + ".3";
  /**
   * Object id id-pda-countryOfCitizenship CountryOfCitizenship ::= PrintableString (SIZE (2)) -- ISO 3166 Country Code
   */
  public static final String id_pda_countryOfCitizenship = id_pda + ".4";
  /**
   * Object id id-pda-countryOfResidence CountryOfResidence ::= PrintableString (SIZE (2)) -- ISO 3166 Country Code
   */
  public static final String id_pda_countryOfResidence = id_pda + ".5";
  /** OID used for creating MS Templates certificate extension */
  public static final String OID_MSTEMPLATE = "1.3.6.1.4.1.311.20.2";
  /** extended key usage OID Intel AMT (out of band) network management */
  public static final String Intel_amt = "2.16.840.1.113741.1.2.3";

  private static final String[] EMAILIDS = { EMAIL, EMAIL1, EMAIL2, EMAIL3 };

  public static final String BEGIN_CERTIFICATE_REQUEST =
    "-----BEGIN CERTIFICATE REQUEST-----";
  public static final String END_CERTIFICATE_REQUEST =
    "-----END CERTIFICATE REQUEST-----";
  public static final String BEGIN_KEYTOOL_CERTIFICATE_REQUEST =
    "-----BEGIN NEW CERTIFICATE REQUEST-----";
  public static final String END_KEYTOOL_CERTIFICATE_REQUEST =
    "-----END NEW CERTIFICATE REQUEST-----";
  public static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
  public static final String END_CERTIFICATE = "-----END CERTIFICATE-----";
  public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
  public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";

  /**
   * See stringToBcX509Name(String, X509NameEntryConverter, boolean), this method uses the default BC converter (X509DefaultEntryConverter) and ldap
   * order
   *
   * @see #stringToBcX509Name(String, X509NameEntryConverter, boolean)
   * @param dn String containing DN that will be transformed into X509Name, The DN string has the format "CN=zz,OU=yy,O=foo,C=SE". Unknown OIDs in
   *            the string will be added to the end positions of OID array.
   *
   * @return X509Name or null if input is null
   */
  public static X509Name stringToBcX509Name(String dn) {
    X509NameEntryConverter converter = new X509DefaultEntryConverter();
    return stringToBcX509Name(dn, converter, true);
  }

  /**
   * Creates a (Bouncycastle) X509Name object from a string with a DN. Known OID (with order) are:
   * <code> EmailAddress, UID, CN, SN (SerialNumber), GivenName, Initials, SurName, T, OU,
   * O, L, ST, DC, C </code> To change order edit 'dnObjects' in this source file. Important NOT to mess with the ordering within this class, since
   * cert vierification on some clients (IE :-() might depend on order.
   *
   * @param dn String containing DN that will be transformed into X509Name, The DN string has the format "CN=zz,OU=yy,O=foo,C=SE". Unknown OIDs in
   *            the string will be added to the end positions of OID array.
   * @param converter BC converter for DirectoryStrings, that determines which encoding is chosen
   * @param ldaporder true if LDAP ordering of DN should be used (default in EJBCA), false for X.500 order, ldap order is CN=A,OU=B,O=C,C=SE, x.500
   *            order is the reverse
   * @return X509Name or null if input is null
   */
  public static X509Name stringToBcX509Name(
    String dn,
    X509NameEntryConverter converter,
    boolean ldaporder
  ) {
    if (dn == null) {
      return null;
    }

    Vector<DERObjectIdentifier> defaultOrdering = new Vector<
      DERObjectIdentifier
    >();
    Vector<String> values = new Vector<String>();
    X509NameTokenizer x509NameTokenizer = new X509NameTokenizer(dn);

    while (x509NameTokenizer.hasMoreTokens()) {
      // This is a pair key=val (CN=xx)
      String pair = x509NameTokenizer.nextToken(); // Will escape '+' and initial '#' chars
      int index = pair.indexOf('=');

      if (index != -1) {
        String key = pair.substring(0, index).toLowerCase().trim();
        String val = pair.substring(index + 1);
        if (val != null) {
          // String whitespace from the beginning of the value, to handle the case
          // where someone type CN = Foo Bar
          val = StringUtils.stripStart(val, null);
        }

        // -- First search the OID by name in declared OID's
        DERObjectIdentifier oid = DnComponents.getOid(key);

        try {
          // -- If isn't declared, we try to create it
          if (oid == null) {
            oid = new DERObjectIdentifier(key);
          }
          defaultOrdering.add(oid);
          values.add(getUnescapedPlus(val));
        } catch (IllegalArgumentException e) {
          // If it is not an OID we will ignore it
          log.warn("Unknown DN component ignored and silently dropped: " + key);
        }
      } else {
        log.warn("Huh, what's this? DN: " + dn + " PAIR: " + pair);
      }
    }

    X509Name x509Name = new X509Name(defaultOrdering, values, converter);

    // -- Reorder fields
    X509Name orderedX509Name = getOrderedX509Name(
      x509Name,
      ldaporder,
      converter
    );

    // log.trace("<stringToBcX509Name");
    return orderedX509Name;
  } // stringToBcX509Name

  // Remove extra '+' character escaping
  private static String getUnescapedPlus(final String value) {
    StringBuilder buf = new StringBuilder(value);
    int index = 0;
    int end = buf.length();
    while (index < end) {
      if (buf.charAt(index) == '\\' && index + 1 != end) {
        char c = buf.charAt(index + 1);
        if (c == '+') {
          buf.deleteCharAt(index);
          end--;
        }
      }
      index++;
    }
    return buf.toString();
  }

  /**
   * Check if the String contains any unescaped '+'. RFC 2253, section 2.2 states that '+' is used for multi-valued RelativeDistinguishedName. BC
   * (version 1.45) currently does not support multi-valued RelativeDistinguishedName, and automatically escapes it instead. We want to detect
   * unescaped '+' chars and warn that this might not be supported in the future if support for multi-valued RDNs is implemented.
   */
  private static void detectUnescapedPlus(String dn) {
    if (dn == null) {
      return;
    }
    StringBuilder buf = new StringBuilder(dn);
    int index = 0;
    int end = buf.length();
    while (index < end) {
      if (buf.charAt(index) == '+') {
        // Found an unescaped '+' character.
        log.warn(
          "DN \"" +
          dn +
          "\" contains an unescaped '+'-character that will be automatically escaped. RFC 2253 reservs this " +
          "for multi-valued RelativeDistinguishedNames. Encourage clients to use '\\+' instead, since future behaviour might change."
        );
      } else if (buf.charAt(index) == '\\') {
        // Found an escape character.
        index++;
      }
      index++;
    }
  }

  /**
   * Every DN-string should look the same. Creates a name string ordered and looking like we want it...
   *
   * @param dn String containing DN
   *
   * @return String containing DN, or null if input is null
   */
  public static String stringToBCDNString(String dn) {
    detectUnescapedPlus(dn); // Log warning if dn contains unescaped '+'
    if (isDNReversed(dn)) {
      dn = reverseDN(dn);
    }
    String ret = null;
    X509Name name = stringToBcX509Name(dn);
    if (name != null) {
      ret = name.toString();
    }
    /*
     * For some databases (MySQL for instance) the database column holding subjectDN is only 250 chars long. There have been strange error
     * reported (clipping DN natuarally) that is hard to debug if DN is more than 250 chars and we don't have a good message
     */
    if ((ret != null) && (ret.length() > 250)) {
      log.info(
        "Warning! DN is more than 250 characters long. Some databases have only 250 characters in the database for SubjectDN. Clipping may occur! DN (" +
        ret.length() +
        " chars): " +
        ret
      );
    }
    return ret;
  }

  /**
   * Convenience method for getting an email addresses from a DN. Uses {@link #getPartsFromDN(String,String)} internally, and searches for
   * {@link #EMAIL}, {@link #EMAIL1}, {@link #EMAIL2}, {@link #EMAIL3} and returns the first one found.
   *
   * @param dn the DN
   *
   * @return ArrayList containing email or empty list if email is not present
   */
  public static ArrayList<String> getEmailFromDN(String dn) {
    if (log.isTraceEnabled()) {
      log.trace(">getEmailFromDN(" + dn + ")");
    }
    ArrayList<String> ret = new ArrayList<String>();
    for (int i = 0; i < EMAILIDS.length; i++) {
      ArrayList<String> emails = getPartsFromDN(dn, EMAILIDS[i]);
      if (!emails.isEmpty()) {
        ret.addAll(emails);
      }
    }
    if (log.isTraceEnabled()) {
      log.trace("<getEmailFromDN(" + dn + "): " + ret.size());
    }
    return ret;
  }

  /**
   * Search for e-mail address, first in SubjectAltName (as in PKIX recommendation) then in subject DN. Original author: Marco Ferrante, (c) 2005
   * CSITA - University of Genoa (Italy)
   *
   * @param certificate
   * @return subject email or null if not present in certificate
   */
  public static String getEMailAddress(Certificate certificate) {
    log.debug("Searching for EMail Address in SubjectAltName");
    if (certificate == null) {
      return null;
    }
    if (certificate instanceof X509Certificate) {
      X509Certificate x509cert = (X509Certificate) certificate;
      try {
        if (x509cert.getSubjectAlternativeNames() != null) {
          for (List<?> item : x509cert.getSubjectAlternativeNames()) {
            Integer type = (Integer) item.get(0);
            if (type.intValue() == 1) {
              return (String) item.get(1);
            }
          }
        }
      } catch (CertificateParsingException e) {
        log.error("Error parsing certificate: ", e);
      }
      log.debug("Searching for EMail Address in Subject DN");
      ArrayList<String> emails = CertTools1.getEmailFromDN(
        x509cert.getSubjectDN().getName()
      );
      if (!emails.isEmpty()) {
        return (String) emails.get(0);
      }
    }
    return null;
  }

  /**
   * Takes a DN and reverses it completely so the first attribute ends up last. C=SE,O=Foo,CN=Bar becomes CN=Bar,O=Foo,C=SE.
   *
   * @param dn String containing DN to be reversed, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz".
   *
   * @return String containing reversed DN
   */
  public static String reverseDN(String dn) {
    if (log.isTraceEnabled()) {
      log.trace(">reverseDN: dn: " + dn);
    }
    String ret = null;
    if (dn != null) {
      String o;
      final BasicX509NameTokenizer xt = new BasicX509NameTokenizer(dn);
      StringBuilder buf = new StringBuilder();
      boolean first = true;
      while (xt.hasMoreTokens()) {
        o = xt.nextToken();
        // log.debug("token: "+o);
        if (!first) {
          buf.insert(0, ",");
        } else {
          first = false;
        }
        buf.insert(0, o);
      }
      if (buf.length() > 0) {
        ret = buf.toString();
      }
    }
    if (log.isTraceEnabled()) {
      log.trace("<reverseDN: resulting dn: " + ret);
    }
    return ret;
  } // reverseDN

  /**
   * Tries to determine if a DN is in reversed form. It does this by taking the last attribute and the first attribute. If the last attribute comes
   * before the first in the dNObjects array the DN is assumed to be in reversed order.
   *
   * The default ordering is: "CN=Tomas, O=PrimeKey, C=SE" (dNObjectsForward ordering in EJBCA) a dn or form "C=SE, O=PrimeKey, CN=Tomas" is
   * reversed.
   *
   *
   * @param dn String containing DN to be checked, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz".
   *
   * @return true if the DN is believed to be in reversed order, false otherwise
   */
  protected static boolean isDNReversed(String dn) {
    /*
     * if (log.isTraceEnabled()) { log.trace(">isDNReversed: dn: " + dn); }
     */
    boolean ret = false;
    if (dn != null) {
      String first = null;
      String last = null;
      X509NameTokenizer xt = new X509NameTokenizer(dn);
      if (xt.hasMoreTokens()) {
        first = xt.nextToken();
      }
      while (xt.hasMoreTokens()) {
        last = xt.nextToken();
      }
      String[] dNObjects = DnComponents.getDnObjects(true);
      if ((first != null) && (last != null)) {
        first = first.substring(0, first.indexOf('='));
        last = last.substring(0, last.indexOf('='));
        int firsti = 0, lasti = 0;
        for (int i = 0; i < dNObjects.length; i++) {
          if (first.toLowerCase().equals(dNObjects[i])) {
            firsti = i;
          }
          if (last.toLowerCase().equals(dNObjects[i])) {
            lasti = i;
          }
        }
        if (lasti < firsti) {
          ret = true;
        }
      }
    }
    /*
     * if (log.isTraceEnabled()) { log.trace("<isDNReversed: " + ret); }
     */
    return ret;
  } // isDNReversed

  /**
   * Gets a specified part of a DN. Specifically the first occurrence it the DN contains several instances of a part (i.e. cn=x, cn=y returns x).
   *
   * @param dn String containing DN, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz".
   * @param dnpart String specifying which part of the DN to get, should be "CN" or "OU" etc.
   *
   * @return String containing dnpart or null if dnpart is not present
   */
  public static String getPartFromDN(String dn, String dnpart) {
    if (log.isTraceEnabled()) {
      log.trace(">getPartFromDN: dn:'" + dn + "', dnpart=" + dnpart);
    }
    String part = null;
    if ((dn != null) && (dnpart != null)) {
      String o;
      dnpart += "="; // we search for 'CN=' etc.
      X509NameTokenizer xt = new X509NameTokenizer(dn);
      while (xt.hasMoreTokens()) {
        o = xt.nextToken();
        // log.debug("checking: "+o.substring(0,dnpart.length()));
        if (
          (o.length() > dnpart.length()) &&
          o.substring(0, dnpart.length()).equalsIgnoreCase(dnpart)
        ) {
          part = o.substring(dnpart.length());

          break;
        }
      }
    }
    if (log.isTraceEnabled()) {
      log.trace("<getpartFromDN: resulting DN part=" + part);
    }
    return part;
  } // getPartFromDN

  /**
   * Gets a specified parts of a DN. Returns all occurences as an ArrayList, also works if DN contains several instances of a part (i.e. cn=x, cn=y
   * returns {x, y, null}).
   *
   * @param dn String containing DN, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz".
   * @param dnpart String specifying which part of the DN to get, should be "CN" or "OU" etc.
   *
   * @return ArrayList containing dnparts or empty list if dnpart is not present
   */
  public static ArrayList<String> getPartsFromDN(String dn, String dnpart) {
    if (log.isTraceEnabled()) {
      log.trace(">getPartsFromDN: dn:'" + dn + "', dnpart=" + dnpart);
    }
    ArrayList<String> parts = new ArrayList<String>();
    if ((dn != null) && (dnpart != null)) {
      String o;
      dnpart += "="; // we search for 'CN=' etc.
      X509NameTokenizer xt = new X509NameTokenizer(dn);
      while (xt.hasMoreTokens()) {
        o = xt.nextToken();
        if (
          (o.length() > dnpart.length()) &&
          o.substring(0, dnpart.length()).equalsIgnoreCase(dnpart)
        ) {
          parts.add(o.substring(dnpart.length()));
        }
      }
    }
    if (log.isTraceEnabled()) {
      log.trace("<getpartsFromDN: resulting DN part=" + parts.toString());
    }
    return parts;
  } // getPartFromDN

  /**
   * Gets a list of all custom OIDs defined in the string. A custom OID is defined as an OID, simply as that. Otherwise, if it is not a custom oid,
   * the DNpart is defined by a name such as CN och rfc822Name. This method only returns a oid once, so if the input string has multiple of the same
   * oid, only one value is returned.
   *
   * @param dn String containing DN, The DN string has the format "C=SE, O=xx, OU=yy, CN=zz", or "rfc822Name=foo@bar.com", etc.
   * @param dnpart String specifying which part of the DN to get, should be "CN" or "OU" etc.
   *
   * @return ArrayList containing unique oids or empty list if no custom OIDs are present
   */
  public static ArrayList<String> getCustomOids(String dn) {
    if (log.isTraceEnabled()) {
      log.trace(">getCustomOids: dn:'" + dn);
    }
    ArrayList<String> parts = new ArrayList<String>();
    if (dn != null) {
      String o;
      X509NameTokenizer xt = new X509NameTokenizer(dn);
      while (xt.hasMoreTokens()) {
        o = xt.nextToken();
        // Try to see if it is a valid OID
        try {
          int i = o.indexOf('=');
          // An oid is never shorter than 3 chars and must start with 1.
          if ((i > 2) && (o.charAt(1) == '.')) {
            String oid = o.substring(0, i);
            // If we have multiple of the same custom oid, don't claim that we have more
            // This method will only return "unique" custom oids.
            if (!parts.contains(oid)) {
              // Check if it is a real oid, if it is not we will ignore it (IllegalArgumentException will be thrown)
              new DERObjectIdentifier(oid);
              parts.add(oid);
            }
          }
        } catch (IllegalArgumentException e) {
          // Not a valid oid
        }
      }
    }
    if (log.isTraceEnabled()) {
      log.trace("<getpartsFromDN: resulting DN part=" + parts.toString());
    }
    return parts;
  } // getPartFromDN

  /**
   * Gets subject DN in the format we are sure about (BouncyCastle),supporting UTF8.
   *
   * @param cert Certificate
   *
   * @return String containing the subjects DN.
   */
  public static String getSubjectDN(Certificate cert) {
    return getDN(cert, 1);
  }

  /**
   * Gets issuer DN in the format we are sure about (BouncyCastle),supporting UTF8.
   *
   * @param cert Certificate
   *
   * @return String containing the issuers DN.
   */
  public static String getIssuerDN(Certificate cert) {
    return getDN(cert, 2);
  }

  /**
   * Gets subject or issuer DN in the format we are sure about (BouncyCastle),supporting UTF8.
   *
   * @param cert X509Certificate
   * @param which 1 = subjectDN, anything else = issuerDN
   *
   * @return String containing the DN.
   */
  private static String getDN(Certificate cert, int which) {
    String ret = null;
    if (cert == null) {
      return null;
    }
    if (cert instanceof X509Certificate) {
      // cert.getType=X.509
      try {
        CertificateFactory cf = CertTools1.getCertificateFactory();
        X509Certificate x509cert = (X509Certificate) cf.generateCertificate(
          new ByteArrayInputStream(cert.getEncoded())
        );
        String dn = null;
        if (which == 1) {
          dn = x509cert.getSubjectDN().toString();
        } else {
          dn = x509cert.getIssuerDN().toString();
        }
        ret = stringToBCDNString(dn);
      } catch (CertificateException ce) {
        log.info("Could not get DN from X509Certificate. " + ce.getMessage());
        log.debug("", ce);
        return null;
      }
    } else if (StringUtils.equals(cert.getType(), "CVC")) {
      CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
      try {
        ReferenceField rf = null;
        if (which == 1) {
          rf = cvccert
            .getCVCertificate()
            .getCertificateBody()
            .getHolderReference();
        } else {
          rf = cvccert
            .getCVCertificate()
            .getCertificateBody()
            .getAuthorityReference();
        }
        if (rf != null) {
          // Construct a "fake" DN which can be used in EJBCA
          // Use only mnemonic and country, since sequence is more of a serialnumber than a DN part
          String dn = "";
          if (rf.getMnemonic() != null) {
            if (StringUtils.isNotEmpty(dn)) {
              dn += ", ";
            }
            dn += "CN=" + rf.getMnemonic();
          }
          if (rf.getCountry() != null) {
            if (StringUtils.isNotEmpty(dn)) {
              dn += ", ";
            }
            dn += "C=" + rf.getCountry();
          }
          ret = stringToBCDNString(dn);
        }
      } catch (NoSuchFieldException e) {
        log.error("NoSuchFieldException: ", e);
        return null;
      }
    }
    return ret;
  }

  /**
   * Gets Serial number of the certificate.
   *
   * @param cert Certificate
   *
   * @return BigInteger containing the certificate serial number. Can be 0 for CVC certificates with alphanumeric serial numbers if the sequence
   *         does not contain any number characters at all.
   * @throws IllegalArgumentException if null input of certificate type is not handled
   */
  public static BigInteger getSerialNumber(Certificate cert) {
    if (cert == null) {
      throw new IllegalArgumentException("Null input");
    }
    BigInteger ret = null;
    if (cert instanceof X509Certificate) {
      X509Certificate xcert = (X509Certificate) cert;
      ret = xcert.getSerialNumber();
    } else if (StringUtils.equals(cert.getType(), "CVC")) {
      // For CVC certificates the sequence field of the HolderReference is kind of a serial number,
      // but if can be alphanumeric which means it can not be made into a BigInteger
      CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
      try {
        String sequence = cvccert
          .getCVCertificate()
          .getCertificateBody()
          .getHolderReference()
          .getSequence();
        ret = getSerialNumberFromString(sequence);
      } catch (NoSuchFieldException e) {
        log.error("getSerialNumber: NoSuchFieldException: ", e);
        ret = BigInteger.valueOf(0);
      }
    } else {
      throw new IllegalArgumentException(
        "getSerialNumber: Certificate of type " +
        cert.getType() +
        " is not implemented"
      );
    }
    return ret;
  }

  /**
   * Gets a serial number in numeric form, it takes - either a hex encoded integer with length != 5 (x.509 certificate) - 5 letter numeric string
   * (cvc), will convert the number to an int - 5 letter alfanumeric string vi some numbers in it (cvc), will convert the numbers in it to a numeric
   * string (remove the letters) and convert to int - 5 letter alfanumeric string with only letters (cvc), will convert to integer from string with
   * radix 36
   *
   * @param sernoString
   * @return BigInteger
   */
  public static BigInteger getSerialNumberFromString(String sernoString) {
    if (sernoString == null) {
      throw new IllegalArgumentException(
        "getSerialNumberFromString: cert is null"
      );
    }
    BigInteger ret;
    if (sernoString.length() != 5) {
      // This can not be a CVC certificate sequence, so it must be a hex encoded regular certificate serial number
      ret = new BigInteger(sernoString, 16);
    } else {
      // We try to handle the different cases of CVC certificate sequences, see StringTools.KEY_SEQUENCE_FORMAT
      try {
        if (NumberUtils.isNumber(sernoString)) {
          ret = NumberUtils.createBigInteger(sernoString);
        } else {
          // check if input is hexadecimal
          log.info(
            "getSerialNumber: Sequence is not a numeric string, trying to extract numerical sequence part."
          );
          StringBuilder buf = new StringBuilder();
          for (int i = 0; i < sernoString.length(); i++) {
            char c = sernoString.charAt(i);
            if (CharUtils.isAsciiNumeric(c)) {
              buf.append(c);
            }
          }
          if (buf.length() > 0) {
            ret = NumberUtils.createBigInteger(buf.toString());
          } else {
            log.info(
              "getSerialNumber: can not extract numeric sequence part, trying alfanumeric value (radix 36)."
            );
            if (sernoString.matches("[0-9A-Z]{1,5}")) {
              int numSeq = Integer.parseInt(sernoString, 36);
              ret = BigInteger.valueOf(numSeq);
            } else {
              log.info(
                "getSerialNumber: Sequence does not contain any numeric parts, returning 0."
              );
              ret = BigInteger.valueOf(0);
            }
          }
        }
      } catch (NumberFormatException e) {
        // If we can't make the sequence into a serial number big integer, set it to 0
        log.debug(
          "getSerialNumber: NumberFormatException for sequence: " + sernoString
        );
        ret = BigInteger.valueOf(0);
      }
    }
    return ret;
  }

  /**
   * Gets Serial number of the certificate as a string. For X509 Certificate this means a HEX encoded BigInteger, and for CVC certificate is means
   * the sequence field of the holder reference.
   *
   * @param cert Certificate
   *
   * @return String to be displayed
   */
  public static String getSerialNumberAsString(Certificate cert) {
    String ret = null;
    if (cert == null) {
      throw new IllegalArgumentException("getSerialNumber: cert is null");
    }
    if (cert instanceof X509Certificate) {
      X509Certificate xcert = (X509Certificate) cert;
      ret = xcert.getSerialNumber().toString(16).toUpperCase();
    } else if (StringUtils.equals(cert.getType(), "CVC")) {
      // For CVC certificates the sequence field of the HolderReference is kind of a serial number,
      // but if can be alphanumeric which means it can not be made into a BigInteger
      CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
      try {
        ret = cvccert
          .getCVCertificate()
          .getCertificateBody()
          .getHolderReference()
          .getSequence();
      } catch (NoSuchFieldException e) {
        log.error("getSerialNumber: NoSuchFieldException: ", e);
        ret = "N/A";
      }
    } else {
      throw new IllegalArgumentException(
        "getSerialNumber: Certificate of type " +
        cert.getType() +
        " is not implemented"
      );
    }
    return ret;
  }

  /**
   * Gets the signature value (the raw signature bits) from the certificate. For an X509 certificate this is the ASN.1 definition which is:
   * signature BIT STRING
   *
   * @param cert Certificate
   *
   * @return byte[] containing the certificate signature bits, if cert is null a byte[] of size 0 is returned.
   */
  public static byte[] getSignature(Certificate cert) {
    byte[] ret = null;
    if (cert == null) {
      ret = new byte[0];
    } else {
      if (cert instanceof X509Certificate) {
        X509Certificate xcert = (X509Certificate) cert;
        ret = xcert.getSignature();
      } else if (StringUtils.equals(cert.getType(), "CVC")) {
        CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
        try {
          ret = cvccert.getCVCertificate().getSignature();
        } catch (NoSuchFieldException e) {
          log.error("NoSuchFieldException: ", e);
          return null;
        }
      }
    }
    return ret;
  }

  /**
   * Gets issuer DN for CRL in the format we are sure about (BouncyCastle),supporting UTF8.
   *
   * @param crl X509RL
   *
   * @return String containing the DN.
   */
  public static String getIssuerDN(X509CRL crl) {
    String dn = null;
    try {
      CertificateFactory cf = CertTools1.getCertificateFactory();
      X509CRL x509crl = (X509CRL) cf.generateCRL(
        new ByteArrayInputStream(crl.getEncoded())
      );
      // log.debug("Created certificate of class: " + x509crl.getClass().getName());
      dn = x509crl.getIssuerDN().toString();
    } catch (CRLException ce) {
      log.error("CRLException: ", ce);
      return null;
    }
    return stringToBCDNString(dn);
  }

  public static Date getNotBefore(Certificate cert) {
    Date ret = null;
    if (cert == null) {
      throw new IllegalArgumentException("getNotBefore: cert is null");
    }
    if (cert instanceof X509Certificate) {
      X509Certificate xcert = (X509Certificate) cert;
      ret = xcert.getNotBefore();
    } else if (StringUtils.equals(cert.getType(), "CVC")) {
      CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
      try {
        ret = cvccert.getCVCertificate().getCertificateBody().getValidFrom();
      } catch (NoSuchFieldException e) {
        // it is not uncommon that this field is missing in CVC certificate requests (it's not in the EAC standard so)
        log.debug("NoSuchFieldException: " + e.getMessage());
        return null;
      }
    }
    return ret;
  }

  public static Date getNotAfter(Certificate cert) {
    Date ret = null;
    if (cert == null) {
      throw new IllegalArgumentException("getNotAfter: cert is null");
    }
    if (cert instanceof X509Certificate) {
      X509Certificate xcert = (X509Certificate) cert;
      ret = xcert.getNotAfter();
    } else if (StringUtils.equals(cert.getType(), "CVC")) {
      CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
      try {
        ret = cvccert.getCVCertificate().getCertificateBody().getValidTo();
      } catch (NoSuchFieldException e) {
        // it is not uncommon that this field is missing in CVC certificate requests (it's not in the EAC standard so)
        log.debug("NoSuchFieldException: " + e.getMessage());
        return null;
      }
    }
    return ret;
  }

  public static CertificateFactory getCertificateFactory(String provider) {
    String prov = provider;
    if (provider == null) {
      prov = "BC";
    }
    if (StringUtils.equals(prov, "BC")) {
      CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    try {
      return CertificateFactory.getInstance("X.509", prov);
    } catch (NoSuchProviderException nspe) {
      log.error("NoSuchProvider: ", nspe);
    } catch (CertificateException ce) {
      log.error("CertificateException: ", ce);
    }
    return null;
  }

  public static CertificateFactory getCertificateFactory() {
    return getCertificateFactory("BC");
  }

  /**
   * Reads a certificate in PEM-format from a file. The file may contain other things, the first certificate in the file is read.
   *
   * @param certFile the file containing the certificate in PEM-format
   * @return Ordered Collection of Certificate, first certificate first, or empty Collection
   * @exception IOException if the filen cannot be read.
   * @exception CertificateException if the filen does not contain a correct certificate.
   */
  public static Collection<Certificate> getCertsFromPEM(String certFile)
    throws IOException, CertificateException {
    if (log.isTraceEnabled()) {
      log.trace(">getCertfromPEM: certFile=" + certFile);
    }
    InputStream inStrm = null;
    Collection<Certificate> certs;
    try {
      inStrm = new FileInputStream(certFile);
      certs = getCertsFromPEM(inStrm);
    } finally {
      if (inStrm != null) {
        inStrm.close();
      }
    }
    if (log.isTraceEnabled()) {
      log.trace("<getCertfromPEM: certFile=" + certFile);
    }
    return certs;
  }

  /**
   * Reads a certificate in PEM-format from an InputStream. The stream may contain other things, the first certificate in the stream is read.
   *
   * @param certstream the input stream containing the certificate in PEM-format
   * @return Ordered Collection of Certificate, first certificate first, or empty Collection
   * @exception IOException if the stream cannot be read.
   * @exception CertificateException if the stream does not contain a correct certificate.
   */
  public static Collection<Certificate> getCertsFromPEM(InputStream certstream)
    throws IOException, CertificateException {
    if (log.isTraceEnabled()) {
      log.trace(">getCertfromPEM");
    }
    ArrayList<Certificate> ret = new ArrayList<Certificate>();
    String beginKeyTrust = "-----BEGIN TRUSTED CERTIFICATE-----";
    String endKeyTrust = "-----END TRUSTED CERTIFICATE-----";
    BufferedReader bufRdr = null;
    ByteArrayOutputStream ostr = null;
    PrintStream opstr = null;
    try {
      bufRdr = new BufferedReader(new InputStreamReader(certstream));
      while (bufRdr.ready()) {
        ostr = new ByteArrayOutputStream();
        opstr = new PrintStream(ostr);
        String temp;
        while (
          (temp = bufRdr.readLine()) != null &&
          !(temp.equals(CertTools1.BEGIN_CERTIFICATE) ||
            temp.equals(beginKeyTrust))
        ) {
          continue;
        }
        if (temp == null) {
          if (ret.isEmpty()) {
            // There was no certificate in the file
            throw new IOException(
              "Error in " +
              certstream.toString() +
              ", missing " +
              CertTools1.BEGIN_CERTIFICATE +
              " boundary"
            );
          } else {
            // There were certificates, but some blank lines or something in the end
            // anyhow, the file has ended so we can break here.
            break;
          }
        }
        while (
          (temp = bufRdr.readLine()) != null &&
          !(temp.equals(CertTools1.END_CERTIFICATE) || temp.equals(endKeyTrust))
        ) {
          opstr.print(temp);
        }
        if (temp == null) {
          throw new IOException(
            "Error in " +
            certstream.toString() +
            ", missing " +
            CertTools1.END_CERTIFICATE +
            " boundary"
          );
        }
        opstr.close();

        byte[] certbuf = Base64.decode(ostr.toByteArray());
        ostr.close();
        // Phweeew, were done, now decode the cert from file back to Certificate object
        Certificate cert = getCertfromByteArray(certbuf);
        ret.add(cert);
      }
    } finally {
      if (bufRdr != null) {
        bufRdr.close();
      }
      if (opstr != null) {
        opstr.close();
      }
      if (ostr != null) {
        ostr.close();
      }
    }
    if (log.isTraceEnabled()) {
      log.trace("<getcertfromPEM:" + ret.size());
    }
    return ret;
  } // getCertsFromPEM

  /**
   * Converts a regular array of certificates into an ArrayList, using the provided provided.
   *
   * @param certs Certificate[] of certificates to convert
   * @param provider provider for example "SUN" or "BC", use null for the default provider (BC)
   * @return An ArrayList of certificates in the same order as the passed in array
   * @throws NoSuchProviderException
   * @throws CertificateException
   */
  public static Collection<Certificate> getCertCollectionFromArray(
    Certificate[] certs,
    String provider
  ) throws CertificateException, NoSuchProviderException {
    if (log.isTraceEnabled()) {
      log.trace(">getCertCollectionFromArray: " + provider);
    }
    ArrayList<Certificate> ret = new ArrayList<Certificate>();
    String prov = provider;
    if (prov == null) {
      prov = "BC";
    }
    for (int i = 0; i < certs.length; i++) {
      Certificate cert = certs[i];
      Certificate newcert = getCertfromByteArray(cert.getEncoded(), prov);
      ret.add(newcert);
    }
    if (log.isTraceEnabled()) {
      log.trace("<getCertCollectionFromArray: " + ret.size());
    }
    return ret;
  }

  /**
   * Returns a certificate in PEM-format.
   *
   * @param certs Collection of Certificate to convert to PEM
   * @return byte array containing PEM certificate
   * @exception CertificateException if the stream does not contain a correct certificate.
   */
  public static byte[] getPEMFromCerts(Collection<Certificate> certs)
    throws CertificateException {
    ByteArrayOutputStream ostr = new ByteArrayOutputStream();
    PrintStream opstr = new PrintStream(ostr);
    Iterator<Certificate> iter = certs.iterator();
    while (iter.hasNext()) {
      Certificate cert = (Certificate) iter.next();
      byte[] certbuf = Base64.encode(cert.getEncoded());
      opstr.println("Subject: " + CertTools1.getSubjectDN(cert));
      opstr.println("Issuer: " + CertTools1.getIssuerDN(cert));
      opstr.println(CertTools1.BEGIN_CERTIFICATE);
      opstr.println(new String(certbuf));
      opstr.println(CertTools1.END_CERTIFICATE);
    }
    opstr.close();
    byte[] ret = ostr.toByteArray();
    return ret;
  }

  /**
   * Returns a CRL in PEM-format.
   *
   * @param crlbytes the der encoded crl bytes to convert to PEM
   * @return byte array containing PEM CRL
   * @exception IOException if the stream cannot be read.
   */
  public static byte[] getPEMFromCrl(byte[] crlbytes) {
    String beginKey = "-----BEGIN X509 CRL-----";
    String endKey = "-----END X509 CRL-----";
    ByteArrayOutputStream ostr = new ByteArrayOutputStream();
    PrintStream opstr = new PrintStream(ostr);
    byte[] crlb64 = Base64.encode(crlbytes);
    opstr.println(beginKey);
    opstr.println(new String(crlb64));
    opstr.println(endKey);
    opstr.close();
    byte[] ret = ostr.toByteArray();
    return ret;
  }

  /**
   * Creates Certificate from byte[], can be either an X509 certificate or a CVCCertificate
   *
   * @param cert byte array containing certificate in binary (DER) format, or PEM encoded X.509 certificate
   * @param provider provider for example "SUN" or "BC", use null for the default provider (BC)
   *
   * @return Certificate
   *
   * @throws CertificateException if the byte array does not contain a proper certificate.
   * @throws IOException if the byte array cannot be read.
   */
  public static Certificate getCertfromByteArray(byte[] cert, String provider)
    throws CertificateException {
    Certificate ret = null;
    String prov = provider;
    if (provider == null) {
      prov = "BC";
    }
    try {
      CertificateFactory cf = CertTools1.getCertificateFactory(prov);
      ret = cf.generateCertificate(new ByteArrayInputStream(cert));
    } catch (CertificateException e) {
      log.debug("CertificateException trying to read X509Certificate.");
    }
    if (ret == null) {
      // We could not create an X509Certificate, see if it is a CVC certificate instead
      try {
        CVCertificate parsedObject = CertificateParser.parseCertificate(cert);
        ret = new CardVerifiableCertificate(parsedObject);
      } catch (ParseException e) {
        log.debug("ParseException trying to read CVCCertificate.");
        throw new CertificateException(
          "Certificate exception trying to read CVCCertificate",
          e
        );
      } catch (ConstructionException e) {
        log.debug("ConstructionException trying to read CVCCertificate.");
        throw new CertificateException(
          "Certificate exception trying to read CVCCertificate",
          e
        );
      } catch (IllegalArgumentException e) {
        log.debug("CertificateException trying to read CVCCertificate.");
        throw new CertificateException(
          "Certificate exception trying to read CVCCertificate",
          e
        );
      }
    }
    return ret;
  }

  /**
   *
   * @throws CertificateException if the byte array does not contain a proper certificate.
   */
  public static Certificate getCertfromByteArray(byte[] cert)
    throws CertificateException {
    return getCertfromByteArray(cert, "BC");
  }

  /**
   * Creates X509CRL from byte[].
   *
   * @param crl byte array containing CRL in DER-format
   *
   * @return X509CRL
   *
   * @throws CertificateException if the byte array does not contain a correct CRL.
   * @throws CRLException if the byte array does not contain a correct CRL.
   */
  public static X509CRL getCRLfromByteArray(byte[] crl) throws CRLException {
    log.trace(">getCRLfromByteArray");
    CertificateFactory cf = CertTools1.getCertificateFactory();
    X509CRL x509crl = (X509CRL) cf.generateCRL(new ByteArrayInputStream(crl));
    log.trace("<getCRLfromByteArray");

    return x509crl;
  } // getCRLfromByteArray

  /**
   * Checks if a certificate is self signed by verifying if subject and issuer are the same.
   *
   * @param cert the certificate that skall be checked.
   *
   * @return boolean true if the certificate has the same issuer and subject, false otherwise.
   */
  public static boolean isSelfSigned(Certificate cert) {
    if (log.isTraceEnabled()) {
      log.trace(
        ">isSelfSigned: cert: " +
        CertTools1.getIssuerDN(cert) +
        "\n" +
        CertTools1.getSubjectDN(cert)
      );
    }
    boolean ret = CertTools1.getSubjectDN(cert).equals(
      CertTools1.getIssuerDN(cert)
    );
    if (log.isTraceEnabled()) {
      log.trace("<isSelfSigned:" + ret);
    }
    return ret;
  } // isSelfSigned

  /**
   * Checks if a certificate is a CA certificate according to BasicConstraints (X.509), or role (CVC). If there is no basic constraints extension on
   * a X.509 certificate, false is returned.
   *
   * @param cert the certificate that skall be checked.
   *
   * @return boolean true if the certificate belongs to a CA.
   */
  public static boolean isCA(Certificate cert) {
    if (log.isTraceEnabled()) {
      log.trace(">isCA");
    }
    boolean ret = false;
    if (cert instanceof X509Certificate) {
      X509Certificate x509cert = (X509Certificate) cert;
      if (x509cert.getBasicConstraints() > -1) {
        ret = true;
      }
    } else if (StringUtils.equals(cert.getType(), "CVC")) {
      CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
      try {
        CVCAuthorizationTemplate templ = cvccert
          .getCVCertificate()
          .getCertificateBody()
          .getAuthorizationTemplate();
        AuthorizationRoleEnum role = templ.getAuthorizationField().getRole();
        if (
          role.equals(AuthorizationRoleEnum.CVCA) ||
          role.equals(AuthorizationRoleEnum.DV_D) ||
          role.equals(AuthorizationRoleEnum.DV_F)
        ) {
          ret = true;
        }
      } catch (NoSuchFieldException e) {
        log.error("NoSuchFieldException: ", e);
      }
    }
    if (log.isTraceEnabled()) {
      log.trace("<isCA:" + ret);
    }
    return ret;
  } // isSelfSigned

  /**
   * Generate a selfsigned certiicate.
   *
   * @param dn subject and issuer DN
   * @param validity in days
   * @param policyId policy string ('2.5.29.32.0') or null
   * @param privKey private key
   * @param pubKey public key
   * @param sigAlg signature algorithm, you can use one of the contants AlgorithmConstants.SIGALG_XXX
   * @param isCA boolean true or false
   *
   * @return X509Certificate, self signed
   *
   * @throws NoSuchAlgorithmException DOCUMENT ME!
   * @throws SignatureException DOCUMENT ME!
   * @throws InvalidKeyException DOCUMENT ME!
   * @throws IllegalStateException
   * @throws CertificateEncodingException
   * @throws NoSuchProviderException
   */
  public static X509Certificate genSelfCert(
    String dn,
    long validity,
    String policyId,
    PrivateKey privKey,
    PublicKey pubKey,
    String sigAlg,
    boolean isCA
  )
    throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateEncodingException, IllegalStateException, NoSuchProviderException {
    return genSelfCert(
      dn,
      validity,
      policyId,
      privKey,
      pubKey,
      sigAlg,
      isCA,
      "BC"
    );
  }

  public static X509Certificate genSelfCert(
    String dn,
    long validity,
    String policyId,
    PrivateKey privKey,
    PublicKey pubKey,
    String sigAlg,
    boolean isCA,
    String provider
  )
    throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateEncodingException, IllegalStateException, NoSuchProviderException {
    int keyusage = X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
    return genSelfCertForPurpose(
      dn,
      validity,
      policyId,
      privKey,
      pubKey,
      sigAlg,
      isCA,
      keyusage,
      provider
    );
  } // genselfCert

  /**
   * Generate a selfsigned certiicate with possibility to specify key usage.
   *
   * @param dn subject and issuer DN
   * @param validity in days
   * @param policyId policy string ('2.5.29.32.0') or null
   * @param privKey private key
   * @param pubKey public key
   * @param sigAlg signature algorithm, you can use one of the contants AlgorithmConstants.SIGALG_XXX
   * @param isCA boolean true or false
   * @param keyusage as defined by constants in X509KeyUsage
   *
   * @return X509Certificate, self signed
   *
   * @throws NoSuchAlgorithmException DOCUMENT ME!
   * @throws SignatureException DOCUMENT ME!
   * @throws InvalidKeyException DOCUMENT ME!
   * @throws IllegalStateException
   * @throws CertificateEncodingException
   * @throws NoSuchProviderException
   */
  public static X509Certificate genSelfCertForPurpose(
    String dn,
    long validity,
    String policyId,
    PrivateKey privKey,
    PublicKey pubKey,
    String sigAlg,
    boolean isCA,
    int keyusage
  )
    throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateEncodingException, IllegalStateException, NoSuchProviderException {
    return genSelfCertForPurpose(
      dn,
      validity,
      policyId,
      privKey,
      pubKey,
      sigAlg,
      isCA,
      keyusage,
      "BC"
    );
  }

  public static X509Certificate genSelfCertForPurpose(
    String dn,
    long validity,
    String policyId,
    PrivateKey privKey,
    PublicKey pubKey,
    String sigAlg,
    boolean isCA,
    int keyusage,
    String provider
  )
    throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CertificateEncodingException, IllegalStateException, NoSuchProviderException {
    // Create self signed certificate
    Date firstDate = new Date();

    // Set back startdate ten minutes to avoid some problems with wrongly set clocks.
    firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));

    Date lastDate = new Date();

    // validity in days = validity*24*60*60*1000 milliseconds
    lastDate.setTime(lastDate.getTime() + (validity * (24 * 60 * 60 * 1000)));

    X509V3CertificateGenerator certgen = new X509V3CertificateGenerator();

    // Transform the PublicKey to be sure we have it in a format that the X509 certificate generator handles, it might be
    // a CVC public key that is passed as parameter
    PublicKey publicKey = null;
    if (pubKey instanceof RSAPublicKey) {
      RSAPublicKey rsapk = (RSAPublicKey) pubKey;
      RSAPublicKeySpec rSAPublicKeySpec = new RSAPublicKeySpec(
        rsapk.getModulus(),
        rsapk.getPublicExponent()
      );
      try {
        publicKey = KeyFactory.getInstance("RSA").generatePublic(
          rSAPublicKeySpec
        );
      } catch (InvalidKeySpecException e) {
        log.error("Error creating RSAPublicKey from spec: ", e);
        publicKey = pubKey;
      }
    } else if (pubKey instanceof ECPublicKey) {
      ECPublicKey ecpk = (ECPublicKey) pubKey;
      try {
        ECPublicKeySpec ecspec = new ECPublicKeySpec(
          ecpk.getW(),
          ecpk.getParams()
        ); // will throw NPE if key is "implicitlyCA"
        publicKey = KeyFactory.getInstance("EC").generatePublic(ecspec);
      } catch (InvalidKeySpecException e) {
        log.error("Error creating ECPublicKey from spec: ", e);
        publicKey = pubKey;
      } catch (NullPointerException e) {
        log.debug(
          "NullPointerException, probably it is implicitlyCA generated keys: " +
          e.getMessage()
        );
        publicKey = pubKey;
      }
    } else {
      log.debug("Not converting key of class. " + pubKey.getClass().getName());
      publicKey = pubKey;
    }

    // Serialnumber is random bits, where random generator is initialized with Date.getTime() when this
    // bean is created.
    byte[] serno = new byte[8];
    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
    random.setSeed(new Date().getTime());
    random.nextBytes(serno);
    certgen.setSerialNumber(new java.math.BigInteger(serno).abs());
    certgen.setNotBefore(firstDate);
    certgen.setNotAfter(lastDate);
    certgen.setSignatureAlgorithm(sigAlg);
    certgen.setSubjectDN(CertTools1.stringToBcX509Name(dn));
    certgen.setIssuerDN(CertTools1.stringToBcX509Name(dn));
    certgen.setPublicKey(publicKey);

    // Basic constranits is always critical and MUST be present at-least in CA-certificates.
    BasicConstraints bc = new BasicConstraints(isCA);
    certgen.addExtension(X509Extensions.BasicConstraints.getId(), true, bc);

    // Put critical KeyUsage in CA-certificates
    if (isCA) {
      X509KeyUsage ku = new X509KeyUsage(keyusage);
      certgen.addExtension(X509Extensions.KeyUsage.getId(), true, ku);
    }

    // Subject and Authority key identifier is always non-critical and MUST be present for certificates to verify in Firefox.
    try {
      if (isCA) {
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(
          (ASN1Sequence) new ASN1InputStream(
            new ByteArrayInputStream(publicKey.getEncoded())
          ).readObject()
        );
        SubjectKeyIdentifier ski = new SubjectKeyIdentifier(spki);

        SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo(
          (ASN1Sequence) new ASN1InputStream(
            new ByteArrayInputStream(publicKey.getEncoded())
          ).readObject()
        );
        AuthorityKeyIdentifier aki = new AuthorityKeyIdentifier(apki);

        certgen.addExtension(
          X509Extensions.SubjectKeyIdentifier.getId(),
          false,
          ski
        );
        certgen.addExtension(
          X509Extensions.AuthorityKeyIdentifier.getId(),
          false,
          aki
        );
      }
    } catch (IOException e) { // do nothing
    }

    // CertificatePolicies extension if supplied policy ID, always non-critical
    if (policyId != null) {
      PolicyInformation pi = new PolicyInformation(
        new DERObjectIdentifier(policyId)
      );
      DERSequence seq = new DERSequence(pi);
      certgen.addExtension(
        X509Extensions.CertificatePolicies.getId(),
        false,
        seq
      );
    }

    X509Certificate selfcert = certgen.generate(privKey, provider);

    return selfcert;
  } // genselfCertForPurpose

  /**
   * Get the authority key identifier from a certificate extensions
   *
   * @param cert certificate containing the extension
   * @return byte[] containing the authority key identifier, or null if it does not exist
   * @throws IOException if extension can not be parsed
   */
  public static byte[] getAuthorityKeyId(Certificate cert) throws IOException {
    if (cert == null) {
      return null;
    }
    if (cert instanceof X509Certificate) {
      X509Certificate x509cert = (X509Certificate) cert;
      byte[] extvalue = x509cert.getExtensionValue("2.5.29.35");
      if (extvalue == null) {
        return null;
      }
      DEROctetString oct = (DEROctetString) (new ASN1InputStream(
          new ByteArrayInputStream(extvalue)
        ).readObject());
      AuthorityKeyIdentifier keyId = new AuthorityKeyIdentifier(
        (ASN1Sequence) new ASN1InputStream(
          new ByteArrayInputStream(oct.getOctets())
        ).readObject()
      );
      return keyId.getKeyIdentifier();
    }
    return null;
  } // getAuthorityKeyId

  /**
   * Get the subject key identifier from a certificate extensions
   *
   * @param cert certificate containing the extension
   * @return byte[] containing the subject key identifier, or null if it does not exist
   * @throws IOException if extension can not be parsed
   */
  public static byte[] getSubjectKeyId(Certificate cert) throws IOException {
    if (cert == null) {
      return null;
    }
    if (cert instanceof X509Certificate) {
      X509Certificate x509cert = (X509Certificate) cert;
      byte[] extvalue = x509cert.getExtensionValue("2.5.29.14");
      if (extvalue == null) {
        return null;
      }
      ASN1OctetString str = ASN1OctetString.getInstance(
        new ASN1InputStream(new ByteArrayInputStream(extvalue)).readObject()
      );
      SubjectKeyIdentifier keyId = SubjectKeyIdentifier.getInstance(
        new ASN1InputStream(
          new ByteArrayInputStream(str.getOctets())
        ).readObject()
      );
      return keyId.getKeyIdentifier();
    }
    return null;
  } // getSubjectKeyId

  /**
   * Get a certificate policy ID from a certificate policies extension
   *
   * @param cert certificate containing the extension
   * @param pos position of the policy id, if several exist, the first is as pos 0
   * @return String with the certificate policy OID
   * @throws IOException if extension can not be parsed
   */
  public static String getCertificatePolicyId(Certificate cert, int pos)
    throws IOException {
    String ret = null;
    if (cert instanceof X509Certificate) {
      X509Certificate x509cert = (X509Certificate) cert;
      byte[] extvalue = x509cert.getExtensionValue(
        X509Extensions.CertificatePolicies.getId()
      );
      if (extvalue == null) {
        return null;
      }
      DEROctetString oct = (DEROctetString) (new ASN1InputStream(
          new ByteArrayInputStream(extvalue)
        ).readObject());
      ASN1Sequence seq = (ASN1Sequence) new ASN1InputStream(
        new ByteArrayInputStream(oct.getOctets())
      ).readObject();
      // Check the size so we don't ArrayIndexOutOfBounds
      if (seq.size() < pos + 1) {
        return null;
      }
      PolicyInformation pol = new PolicyInformation(
        (ASN1Sequence) seq.getObjectAt(pos)
      );
      ret = pol.getPolicyIdentifier().getId();
    }
    return ret;
  } // getCertificatePolicyId

  /**
   * Gets the Microsoft specific UPN altName (altName, OtherName).
   *
   * UPN is an OtherName Subject Alternative Name:
   *
   * OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY DEFINED BY type-id }
   *
   * UPN ::= UTF8String
   *
   * @param cert certificate containing the extension
   * @return String with the UPN name or null if the altName does not exist
   */
  public static String getUPNAltName(Certificate cert)
    throws IOException, CertificateParsingException {
    String ret = null;
    if (cert instanceof X509Certificate) {
      X509Certificate x509cert = (X509Certificate) cert;
      Collection<List<?>> altNames = x509cert.getSubjectAlternativeNames();
      if (altNames != null) {
        Iterator<List<?>> i = altNames.iterator();
        while (i.hasNext()) {
          ASN1Sequence seq = getAltnameSequence((List<?>) i.next());
          ret = getUPNStringFromSequence(seq);
          if (ret != null) {
            break;
          }
        }
      }
    }
    return ret;
  } // getUPNAltName

  /**
   * Helper method for the above method
   *
   * @param seq the OtherName sequence
   */
  private static String getUPNStringFromSequence(ASN1Sequence seq) {
    if (seq != null) {
      // First in sequence is the object identifier, that we must check
      DERObjectIdentifier id = DERObjectIdentifier.getInstance(
        seq.getObjectAt(0)
      );
      if (id.getId().equals(CertTools1.UPN_OBJECTID)) {
        ASN1TaggedObject obj = (ASN1TaggedObject) seq.getObjectAt(1);
        DERUTF8String str = DERUTF8String.getInstance(obj.getObject());
        return str.getString();
      }
    }
    return null;
  }

  /**
   * Helper method to get MS GUID from GeneralName otherName sequence
   *
   * @param seq the OtherName sequence
   */
  private static String getGUIDStringFromSequence(ASN1Sequence seq) {
    String ret = null;
    if (seq != null) {
      // First in sequence is the object identifier, that we must check
      DERObjectIdentifier id = DERObjectIdentifier.getInstance(
        seq.getObjectAt(0)
      );
      if (id.getId().equals(CertTools1.GUID_OBJECTID)) {
        ASN1TaggedObject obj = (ASN1TaggedObject) seq.getObjectAt(1);
        ASN1OctetString str = ASN1OctetString.getInstance(obj.getObject());
        ret = new String(Hex.encode(str.getOctets()));
      }
    }
    return ret;
  }

  /**
   * Helper method for getting kerberos 5 principal name (altName, OtherName)
   *
   * Krb5PrincipalName is an OtherName Subject Alternative Name
   *
   * String representation is in form "principalname1/principalname2@realm"
   *
   * KRB5PrincipalName ::= SEQUENCE { realm [0] Realm, principalName [1] PrincipalName }
   *
   * Realm ::= KerberosString
   *
   * PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF KerberosString }
   *
   * The new (post-RFC 1510) type KerberosString, defined below, is a GeneralString that is constrained to contain only characters in IA5String.
   *
   * KerberosString ::= GeneralString (IA5String)
   *
   * Int32 ::= INTEGER (-2147483648..2147483647) -- signed values representable in 32 bits
   *
   * @param seq the OtherName sequence
   * @return String with the krb5 name in the form of "principal1/principal2@realm" or null if the altName does not exist
   */
  @SuppressWarnings("unchecked")
  protected static String getKrb5PrincipalNameFromSequence(ASN1Sequence seq) {
    String ret = null;
    if (seq != null) {
      // First in sequence is the object identifier, that we must check
      DERObjectIdentifier id = DERObjectIdentifier.getInstance(
        seq.getObjectAt(0)
      );
      if (id.getId().equals(CertTools1.KRB5PRINCIPAL_OBJECTID)) {
        // Get the KRB5PrincipalName sequence
        ASN1TaggedObject oobj = (ASN1TaggedObject) seq.getObjectAt(1);
        // After encoding in a cert, it is tagged an extra time...
        DERObject obj = oobj.getObject();
        if (obj instanceof ASN1TaggedObject) {
          obj = ASN1TaggedObject.getInstance(obj).getObject();
        }
        ASN1Sequence krb5Seq = ASN1Sequence.getInstance(obj);
        // Get the Realm tagged as 0
        ASN1TaggedObject robj = (ASN1TaggedObject) krb5Seq.getObjectAt(0);
        DERGeneralString realmObj = DERGeneralString.getInstance(
          robj.getObject()
        );
        String realm = realmObj.getString();
        // Get the PrincipalName tagged as 1
        ASN1TaggedObject pobj = (ASN1TaggedObject) krb5Seq.getObjectAt(1);
        // This is another sequence of type and name
        ASN1Sequence nseq = ASN1Sequence.getInstance(pobj.getObject());
        // Get the name tagged as 1
        ASN1TaggedObject nobj = (ASN1TaggedObject) nseq.getObjectAt(1);
        // The name is yet another sequence of GeneralString
        ASN1Sequence sseq = ASN1Sequence.getInstance(nobj.getObject());
        Enumeration<ASN1Object> en = sseq.getObjects();
        while (en.hasMoreElements()) {
          ASN1Object o = (ASN1Object) en.nextElement();
          DERGeneralString str = DERGeneralString.getInstance(o);
          if (ret != null) {
            ret += "/" + str.getString();
          } else {
            ret = str.getString();
          }
        }
        // Add the realm in the end so we have "principal@realm"
        ret += "@" + realm;
      }
    }
    return ret;
  }

  /**
   * Gets the Microsoft specific GUID altName, that is encoded as an octect string.
   *
   * @param cert certificate containing the extension
   * @return String with the hex-encoded GUID byte array or null if the altName does not exist
   */
  public static String getGuidAltName(Certificate cert)
    throws IOException, CertificateParsingException {
    if (cert instanceof X509Certificate) {
      X509Certificate x509cert = (X509Certificate) cert;
      Collection<List<?>> altNames = x509cert.getSubjectAlternativeNames();
      if (altNames != null) {
        Iterator<List<?>> i = altNames.iterator();
        while (i.hasNext()) {
          ASN1Sequence seq = getAltnameSequence((List<?>) i.next());
          if (seq != null) {
            String guid = CertTools1.getGUIDStringFromSequence(seq);
            if (guid != null) {
              return guid;
            }
          }
        }
      }
    }
    return null;
  } // getGuidAltName

  /**
   * Helper for the above methods
   */
  private static ASN1Sequence getAltnameSequence(List<?> listitem) {
    Integer no = (Integer) listitem.get(0);
    if (no.intValue() == 0) {
      byte[] altName = (byte[]) listitem.get(1);
      return getAltnameSequence(altName);
    }
    return null;
  }

  private static ASN1Sequence getAltnameSequence(byte[] value) {
    DERObject oct = null;
    try {
      oct = (new ASN1InputStream(new ByteArrayInputStream(value)).readObject());
    } catch (IOException e) {
      throw new RuntimeException("Could not read ASN1InputStream", e);
    }
    ASN1Sequence seq = ASN1Sequence.getInstance(oct);
    return seq;
  }

  /**
   * Gets an altName string from an X509Extension
   *
   * @param ext X509Extension with AlternativeNames
   * @return String as defined in method getSubjectAlternativeName
   */
  public static String getAltNameStringFromExtension(X509Extension ext) {
    String altName = null;
    // GeneralNames
    ASN1OctetString octs = ext.getValue();
    if (octs != null) {
      ASN1InputStream aIn = new ASN1InputStream(
        new ByteArrayInputStream(octs.getOctets())
      );
      DERObject obj;
      try {
        obj = aIn.readObject();
        GeneralNames gan = GeneralNames.getInstance(obj);
        GeneralName[] gns = gan.getNames();
        for (int i = 0; i < gns.length; i++) {
          GeneralName gn = gns[i];
          int tag = gn.getTagNo();
          DEREncodable name = gn.getName();
          String str = CertTools1.getGeneralNameString(tag, name);
          if (altName == null) {
            altName = str;
          } else {
            altName += ", " + str;
          }
        }
      } catch (IOException e) {
        log.error("IOException parsing altNames: ", e);
        return null;
      }
    }
    return altName;
  }

  /**
   * SubjectAltName ::= GeneralNames
   *
   * GeneralNames :: = SEQUENCE SIZE (1..MAX) OF GeneralName
   *
   * GeneralName ::= CHOICE { otherName [0] OtherName, rfc822Name [1] IA5String, dNSName [2] IA5String, x400Address [3] ORAddress, directoryName [4]
   * Name, ediPartyName [5] EDIPartyName, uniformResourceIdentifier [6] IA5String, iPAddress [7] OCTET STRING, registeredID [8] OBJECT IDENTIFIER}
   *
   * SubjectAltName is of form \"rfc822Name=<email>, dNSName=<host name>, uniformResourceIdentifier=<http://host.com/>, iPAddress=<address>,
   * guid=<globally unique id>, directoryName=<CN=testDirName|dir|name>
   *
   * Supported altNames are upn, krb5principal, rfc822Name, uniformResourceIdentifier, dNSName, iPAddress, directoryName
   *
   * @author Marco Ferrante, (c) 2005 CSITA - University of Genoa (Italy)
   * @author Tomas Gustavsson
   * @param certificate containing alt names
   * @return String containing altNames of form
   *         "rfc822Name=email, dNSName=hostname, uniformResourceIdentifier=uri, iPAddress=ip, upn=upn, directoryName=CN=testDirName|dir|name" or
   *         empty string if no altNames exist. Values in returned String is from CertTools constants. AltNames not supported are simply not shown
   *         in the resulting string.
   */
  public static String getSubjectAlternativeName(Certificate certificate) {
    if (log.isDebugEnabled()) {
      log.debug(">getSubjectAlternativeName");
    }
    String result = "";
    if (certificate instanceof X509Certificate) {
      X509Certificate x509cert = (X509Certificate) certificate;

      Collection<List<?>> altNames = null;

      try {
        altNames = x509cert.getSubjectAlternativeNames();
      } catch (CertificateParsingException e) {
        throw new RuntimeException("Could not parse certificate", e);
      }

      if (altNames == null) {
        return null;
      }
      Iterator<List<?>> iter = altNames.iterator();
      String append = "";
      while (iter.hasNext()) {
        List<?> item = iter.next();
        Integer type = (Integer) item.get(0);
        Object value = item.get(1);
        if (!StringUtils.isEmpty(result)) {
          // Result already contains one altname, so we have to add comma if there are more altNames
          append = ", ";
        }
        switch (type.intValue()) {
          case 0:
            ASN1Sequence seq = getAltnameSequence(item);
            String upn = getUPNStringFromSequence(seq);
            // OtherName can be something else besides UPN
            if (upn != null) {
              result += append + CertTools1.UPN + "=" + upn;
            } else {
              String krb5Principal = getKrb5PrincipalNameFromSequence(seq);
              if (krb5Principal != null) {
                result +=
                  append + CertTools1.KRB5PRINCIPAL + "=" + krb5Principal;
              } else {
                String guid = getGUIDStringFromSequence(seq);
                if (guid != null) {
                  result += append + CertTools1.GUID + "=" + guid;
                }
              }
            }
            break;
          case 1:
            result += append + CertTools1.EMAIL + "=" + (String) value;
            break;
          case 2:
            result += append + CertTools1.DNS + "=" + (String) value;
            break;
          case 3: // SubjectAltName of type x400Address not supported
            break;
          case 4:
            result += append + CertTools1.DIRECTORYNAME + "=" + (String) value;
            break;
          case 5: // SubjectAltName of type ediPartyName not supported
            break;
          case 6:
            result += append + CertTools1.URI + "=" + (String) value;
            break;
          case 7:
            result += append + CertTools1.IPADDR + "=" + (String) value;
            break;
          default: // SubjectAltName of unknown type
            break;
        }
      }
      if (StringUtils.isEmpty(result)) {
        return null;
      }
    }
    return result;
  }

  /**
   * From an altName string as defined in getSubjectAlternativeName
   *
   * @param altName
   * @return ASN.1 GeneralNames
   * @see #getSubjectAlternativeName
   */
  public static GeneralNames getGeneralNamesFromAltName(String altName) {
    if (log.isTraceEnabled()) {
      log.trace(">getGeneralNamesFromAltName: " + altName);
    }
    ASN1EncodableVector vec = new ASN1EncodableVector();

    ArrayList<String> emails = CertTools1.getEmailFromDN(altName);
    if (!emails.isEmpty()) {
      Iterator<String> iter = emails.iterator();
      while (iter.hasNext()) {
        GeneralName gn = new GeneralName(
          1,
          new DERIA5String((String) iter.next())
        );
        vec.add(gn);
      }
    }

    ArrayList<String> dns = CertTools1.getPartsFromDN(altName, CertTools1.DNS);
    if (!dns.isEmpty()) {
      Iterator<String> iter = dns.iterator();
      while (iter.hasNext()) {
        GeneralName gn = new GeneralName(
          2,
          new DERIA5String((String) iter.next())
        );
        vec.add(gn);
      }
    }

    String directoryName = getDirectoryStringFromAltName(altName);
    if (directoryName != null) {
      X509Name x509DirectoryName = new X509Name(directoryName);
      GeneralName gn = new GeneralName(4, x509DirectoryName);
      vec.add(gn);
    }

    ArrayList<String> uri = CertTools1.getPartsFromDN(altName, CertTools1.URI);
    if (!uri.isEmpty()) {
      Iterator<String> iter = uri.iterator();
      while (iter.hasNext()) {
        GeneralName gn = new GeneralName(
          6,
          new DERIA5String((String) iter.next())
        );
        vec.add(gn);
      }
    }
    uri = CertTools1.getPartsFromDN(altName, CertTools1.URI1);
    if (!uri.isEmpty()) {
      Iterator<String> iter = uri.iterator();
      while (iter.hasNext()) {
        GeneralName gn = new GeneralName(
          6,
          new DERIA5String((String) iter.next())
        );
        vec.add(gn);
      }
    }
    uri = CertTools1.getPartsFromDN(altName, CertTools1.URI2);
    if (!uri.isEmpty()) {
      Iterator<String> iter = uri.iterator();
      while (iter.hasNext()) {
        GeneralName gn = new GeneralName(
          6,
          new DERIA5String((String) iter.next())
        );
        vec.add(gn);
      }
    }

    ArrayList<String> ipstr = CertTools1.getPartsFromDN(
      altName,
      CertTools1.IPADDR
    );
    if (!ipstr.isEmpty()) {
      Iterator<String> iter = ipstr.iterator();
      while (iter.hasNext()) {
        byte[] ipoctets = StringTools.ipStringToOctets((String) iter.next());
        GeneralName gn = new GeneralName(7, new DEROctetString(ipoctets));
        vec.add(gn);
      }
    }

    // UPN is an OtherName see method getUpn... for asn.1 definition
    ArrayList<String> upn = CertTools1.getPartsFromDN(altName, CertTools1.UPN);
    if (!upn.isEmpty()) {
      Iterator<String> iter = upn.iterator();
      while (iter.hasNext()) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERObjectIdentifier(CertTools1.UPN_OBJECTID));
        v.add(
          new DERTaggedObject(true, 0, new DERUTF8String((String) iter.next()))
        );
        // GeneralName gn = new GeneralName(new DERSequence(v), 0);
        DERObject gn = new DERTaggedObject(false, 0, new DERSequence(v));
        vec.add(gn);
      }
    }

    ArrayList<String> guid = CertTools1.getPartsFromDN(
      altName,
      CertTools1.GUID
    );
    if (!guid.isEmpty()) {
      Iterator<String> iter = guid.iterator();
      while (iter.hasNext()) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        byte[] guidbytes = Hex.decode((String) iter.next());
        if (guidbytes != null) {
          v.add(new DERObjectIdentifier(CertTools1.GUID_OBJECTID));
          v.add(new DERTaggedObject(true, 0, new DEROctetString(guidbytes)));
          DERObject gn = new DERTaggedObject(false, 0, new DERSequence(v));
          vec.add(gn);
        } else {
          log.error("Cannot decode hexadecimal guid: " + guid);
        }
      }
    }

    // Krb5PrincipalName is an OtherName, see method getKrb5Principal...for ASN.1 definition
    ArrayList<String> krb5principalname = CertTools1.getPartsFromDN(
      altName,
      CertTools1.KRB5PRINCIPAL
    );
    if (!krb5principalname.isEmpty()) {
      Iterator<String> iter = krb5principalname.iterator();
      while (iter.hasNext()) {
        // Start by parsing the input string to separate it in different parts
        String principalString = (String) iter.next();
        if (log.isDebugEnabled()) {
          log.debug("principalString: " + principalString);
        }
        // The realm is the last part moving back until an @
        int index = principalString.lastIndexOf('@');
        String realm = "";
        if (index > 0) {
          realm = principalString.substring(index + 1);
        }
        if (log.isDebugEnabled()) {
          log.debug("realm: " + realm);
        }
        // Now we can have several principals separated by /
        ArrayList<String> principalarr = new ArrayList<String>();
        int jndex = 0;
        int bindex = 0;
        while (jndex < index) {
          // Loop and add all strings separated by /
          jndex = principalString.indexOf('/', bindex);
          if (jndex == -1) {
            jndex = index;
          }
          String s = principalString.substring(bindex, jndex);
          if (log.isDebugEnabled()) {
            log.debug("adding principal name: " + s);
          }
          principalarr.add(s);
          bindex = jndex + 1;
        }

        // Now we must construct the rather complex asn.1...
        ASN1EncodableVector v = new ASN1EncodableVector(); // this is the OtherName
        v.add(new DERObjectIdentifier(CertTools1.KRB5PRINCIPAL_OBJECTID));

        // First the Krb5PrincipalName sequence
        ASN1EncodableVector krb5p = new ASN1EncodableVector();
        // The realm is the first tagged GeneralString
        krb5p.add(new DERTaggedObject(true, 0, new DERGeneralString(realm)));
        // Second is the sequence of principal names, which is at tagged position 1 in the krb5p
        ASN1EncodableVector principals = new ASN1EncodableVector();
        // According to rfc4210 the type NT-UNKNOWN is 0, and according to some other rfc this type should be used...
        principals.add(new DERTaggedObject(true, 0, new DERInteger(0)));
        // The names themselves are yet another sequence
        Iterator<String> i = principalarr.iterator();
        ASN1EncodableVector names = new ASN1EncodableVector();
        while (i.hasNext()) {
          String principalName = (String) i.next();
          names.add(new DERGeneralString(principalName));
        }
        principals.add(new DERTaggedObject(true, 1, new DERSequence(names)));
        krb5p.add(new DERTaggedObject(true, 1, new DERSequence(principals)));

        v.add(new DERTaggedObject(true, 0, new DERSequence(krb5p)));
        DERObject gn = new DERTaggedObject(false, 0, new DERSequence(v));
        vec.add(gn);
      }
    }

    // To support custom OIDs in altNames, they must be added as an OtherName of plain type UTF8String
    ArrayList<String> customoids = CertTools1.getCustomOids(altName);
    if (!customoids.isEmpty()) {
      Iterator<String> iter = customoids.iterator();
      while (iter.hasNext()) {
        String oid = (String) iter.next();
        ArrayList<String> oidval = CertTools1.getPartsFromDN(altName, oid);
        if (!oidval.isEmpty()) {
          Iterator<String> valiter = oidval.iterator();
          while (valiter.hasNext()) {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new DERObjectIdentifier(oid));
            v.add(
              new DERTaggedObject(
                true,
                0,
                new DERUTF8String((String) valiter.next())
              )
            );
            DERObject gn = new DERTaggedObject(false, 0, new DERSequence(v));
            vec.add(gn);
          }
        }
      }
    }

    GeneralNames ret = null;
    if (vec.size() > 0) {
      ret = new GeneralNames(new DERSequence(vec));
    }
    return ret;
  }

  /**
   * GeneralName ::= CHOICE { otherName [0] OtherName, rfc822Name [1] IA5String, dNSName [2] IA5String, x400Address [3] ORAddress, directoryName [4]
   * Name, ediPartyName [5] EDIPartyName, uniformResourceIdentifier [6] IA5String, iPAddress [7] OCTET STRING, registeredID [8] OBJECT IDENTIFIER}
   *
   * @param tag the no tag 0-8
   * @param value the DEREncodable value as returned by GeneralName.getName()
   * @return String in form rfc822Name=<email> or uri=<uri> etc
   * @throws IOException
   * @see #getSubjectAlternativeName
   */
  public static String getGeneralNameString(int tag, DEREncodable value)
    throws IOException {
    String ret = null;
    switch (tag) {
      case 0:
        ASN1Sequence seq = getAltnameSequence(
          value.getDERObject().getEncoded()
        );
        String upn = getUPNStringFromSequence(seq);
        // OtherName can be something else besides UPN
        if (upn != null) {
          ret = CertTools1.UPN + "=" + upn;
        } else {
          String krb5Principal = getKrb5PrincipalNameFromSequence(seq);
          if (krb5Principal != null) {
            ret = CertTools1.KRB5PRINCIPAL + "=" + krb5Principal;
          }
        }
        break;
      case 1:
        ret =
          CertTools1.EMAIL + "=" + DERIA5String.getInstance(value).getString();
        break;
      case 2:
        ret =
          CertTools1.DNS + "=" + DERIA5String.getInstance(value).getString();
        break;
      case 3: // SubjectAltName of type x400Address not supported
        break;
      case 4: // SubjectAltName of type directoryName not supported
        break;
      case 5: // SubjectAltName of type ediPartyName not supported
        break;
      case 6:
        ret =
          CertTools1.URI + "=" + DERIA5String.getInstance(value).getString();
        break;
      case 7:
        ASN1OctetString oct = ASN1OctetString.getInstance(value);
        ret =
          CertTools1.IPADDR +
          "=" +
          StringTools.ipOctetsToString(oct.getOctets());
        break;
      default: // SubjectAltName of unknown type
        break;
    }
    return ret;
  }

  /**
   * Check the certificate with CA certificate.
   *
   * @param certificate cert to verify
   * @param caCertPath collection of X509Certificate
   * @return true if verified OK
   * @throws Exception if verification failed
   */
  public static boolean verify(
    Certificate certificate,
    Collection<Certificate> caCertPath
  ) throws Exception {
    try {
      ArrayList<Certificate> certlist = new ArrayList<Certificate>();
      // Create CertPath
      certlist.add(certificate);
      // Add other certs...
      CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
      java.security.cert.CertPath cp = cf.generateCertPath(certlist);
      // Create TrustAnchor. Since EJBCA use BouncyCastle provider, we assume
      // certificate already in correct order
      X509Certificate[] cac = (X509Certificate[]) caCertPath.toArray(
        new X509Certificate[] {}
      );
      java.security.cert.TrustAnchor anchor =
        new java.security.cert.TrustAnchor(cac[0], null);
      // Set the PKIX parameters
      java.security.cert.PKIXParameters params =
        new java.security.cert.PKIXParameters(
          java.util.Collections.singleton(anchor)
        );
      params.setRevocationEnabled(false);
      java.security.cert.CertPathValidator cpv =
        java.security.cert.CertPathValidator.getInstance("PKIX", "BC");
      java.security.cert.PKIXCertPathValidatorResult result =
        (java.security.cert.PKIXCertPathValidatorResult) cpv.validate(
          cp,
          params
        );
      if (log.isDebugEnabled()) {
        log.debug("Certificate verify result: " + result.toString());
      }
    } catch (java.security.cert.CertPathValidatorException cpve) {
      throw new Exception(
        "Invalid certificate or certificate not issued by specified CA: " +
        cpve.getMessage()
      );
    } catch (Exception e) {
      throw new Exception(
        "Error checking certificate chain: " + e.getMessage()
      );
    }
    return true;
  }

  /**
   * Checks that the given date is within the certificate's validity period. In other words, this determines whether the certificate would be valid
   * at the given date/time.
   *
   * This utility class is only a helper to get the same behavior as the standard java.security.cert API regardless if using X.509 or CV
   * Certificate.
   *
   * @param cert certificate to verify, if null the method returns immediately, null does not have a validity to check.
   * @param date the Date to check against to see if this certificate is valid at that date/time.
   * @throws NoSuchFieldException
   * @throws CertificateExpiredException - if the certificate has expired with respect to the date supplied.
   * @throws CertificateNotYetValidException - if the certificate is not yet valid with respect to the date supplied.
   * @see java.security.cert.X509Certificate#checkValidity(Date)
   */
  public static void checkValidity(Certificate cert, Date date)
    throws CertificateExpiredException, CertificateNotYetValidException {
    if (cert != null) {
      if (cert instanceof X509Certificate) {
        X509Certificate xcert = (X509Certificate) cert;
        xcert.checkValidity(date);
      } else if (StringUtils.equals(cert.getType(), "CVC")) {
        CardVerifiableCertificate cvccert = (CardVerifiableCertificate) cert;
        try {
          Date start = cvccert
            .getCVCertificate()
            .getCertificateBody()
            .getValidFrom();
          Date end = cvccert
            .getCVCertificate()
            .getCertificateBody()
            .getValidTo();
          if (start.after(date)) {
            String msg =
              "Certificate startDate '" +
              start +
              "' is after check date '" +
              date +
              "'";
            if (log.isTraceEnabled()) {
              log.trace(msg);
            }
            throw new CertificateNotYetValidException(msg);
          }
          if (end.before(date)) {
            String msg =
              "Certificate endDate '" +
              end +
              "' is before check date '" +
              date +
              "'";
            if (log.isTraceEnabled()) {
              log.trace(msg);
            }
            throw new CertificateExpiredException(msg);
          }
        } catch (NoSuchFieldException e) {
          log.error("NoSuchFieldException: ", e);
        }
      }
    }
  }

  /**
   * Return the CRL distribution point URL from a certificate.
   */
  public static URL getCrlDistributionPoint(Certificate certificate)
    throws CertificateParsingException {
    if (certificate instanceof X509Certificate) {
      X509Certificate x509cert = (X509Certificate) certificate;
      try {
        DERObject obj = getExtensionValue(
          x509cert,
          X509Extensions.CRLDistributionPoints.getId()
        );
        if (obj == null) {
          return null;
        }
        ASN1Sequence distributionPoints = (ASN1Sequence) obj;
        for (int i = 0; i < distributionPoints.size(); i++) {
          ASN1Sequence distrPoint =
            (ASN1Sequence) distributionPoints.getObjectAt(i);
          for (int j = 0; j < distrPoint.size(); j++) {
            ASN1TaggedObject tagged = (ASN1TaggedObject) distrPoint.getObjectAt(
              j
            );
            if (tagged.getTagNo() == 0) {
              String url = getStringFromGeneralNames(tagged.getObject());
              if (url != null) {
                return new URL(url);
              }
            }
          }
        }
      } catch (Exception e) {
        log.error("Error parsing CrlDistributionPoint", e);
        throw new CertificateParsingException(e.toString());
      }
    }
    return null;
  }

  /**
   * Returns OCSP URL that is inside AuthorithInformationAccess extension, or null.
   *
   * @param cert is the certificate to parse
   * @throws CertificateParsingException
   */
  public static String getAuthorityInformationAccessOcspUrl(Certificate cert)
    throws CertificateParsingException {
    String ret = null;
    if (cert instanceof X509Certificate) {
      X509Certificate x509cert = (X509Certificate) cert;
      try {
        DERObject obj = getExtensionValue(
          x509cert,
          X509Extensions.AuthorityInfoAccess.getId()
        );
        if (obj == null) {
          return null;
        }
        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(
          obj
        );
        AccessDescription[] ad = aia.getAccessDescriptions();
        if ((ad != null) && (ad.length > 0)) {
          for (int i = 0; i < ad.length; i++) {
            if (
              ad[i].getAccessMethod()
                .equals(X509ObjectIdentifiers.ocspAccessMethod)
            ) {
              GeneralName gn = ad[i].getAccessLocation();
              if (gn.getTagNo() == 6) {
                DERIA5String str = DERIA5String.getInstance(gn.getDERObject());
                ret = str.getString();
                break; // no need to go on any further, we got a value
              }
            }
          }
        }
      } catch (Exception e) {
        log.error("Error parsing AuthorityInformationAccess", e);
        throw new CertificateParsingException(e.toString());
      }
    }
    return ret;
  }

  /**
   * Return an Extension DERObject from a certificate
   */
  protected static DERObject getExtensionValue(
    X509Certificate cert,
    String oid
  ) throws IOException {
    if (cert == null) {
      return null;
    }
    byte[] bytes = cert.getExtensionValue(oid);
    if (bytes == null) {
      return null;
    }
    ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
    ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
    aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
    return aIn.readObject();
  } // getExtensionValue

  /**
   * Gets a URI string from a GeneralNames structure.
   *
   * @param names DER GeneralNames object, that is a sequence of DERTaggedObject
   * @return String with URI if tagNo is 6 (uniformResourceIdentifier), null otherwise
   */
  private static String getStringFromGeneralNames(DERObject names) {
    ASN1Sequence namesSequence = ASN1Sequence.getInstance(
      (ASN1TaggedObject) names,
      false
    );
    if (namesSequence.size() == 0) {
      return null;
    }
    DERTaggedObject taggedObject = (DERTaggedObject) namesSequence.getObjectAt(
      0
    );
    if (taggedObject.getTagNo() != 6) { // uniformResourceIdentifier [6] IA5String,
      return null;
    }
    return new String(
      ASN1OctetString.getInstance(taggedObject, false).getOctets()
    );
  } // getStringFromGeneralNames

  /**
   * Generate SHA1 fingerprint of certificate in string representation.
   *
   * @param cert Certificate.
   *
   * @return String containing hex format of SHA1 fingerprint, or null if input is null.
   */
  public static String getFingerprintAsString(Certificate cert) {
    if (cert == null) {
      return null;
    }
    try {
      byte[] res = generateSHA1Fingerprint(cert.getEncoded());

      return new String(Hex.encode(res));
    } catch (CertificateEncodingException cee) {
      log.error("Error encoding certificate.", cee);
    }

    return null;
  }

  /**
   * Generate SHA1 fingerprint of CRL in string representation.
   *
   * @param crl X509CRL.
   *
   * @return String containing hex format of SHA1 fingerprint.
   */
  public static String getFingerprintAsString(X509CRL crl) {
    try {
      byte[] res = generateSHA1Fingerprint(crl.getEncoded());

      return new String(Hex.encode(res));
    } catch (CRLException ce) {
      log.error("Error encoding CRL.", ce);
    }

    return null;
  }

  /**
   * Generate SHA1 fingerprint of byte array in string representation.
   *
   * @param in byte array to fingerprint.
   *
   * @return String containing hex format of SHA1 fingerprint.
   */
  public static String getFingerprintAsString(byte[] in) {
    byte[] res = generateSHA1Fingerprint(in);
    return new String(Hex.encode(res));
  }

  /**
   * Generate a SHA1 fingerprint from a byte array containing a certificate
   *
   * @param ba Byte array containing DER encoded Certificate or CRL.
   *
   * @return Byte array containing SHA1 hash of DER encoded certificate.
   */
  public static byte[] generateSHA1Fingerprint(byte[] ba) {
    // log.trace(">generateSHA1Fingerprint");
    try {
      MessageDigest md = MessageDigest.getInstance("SHA1");

      return md.digest(ba);
    } catch (NoSuchAlgorithmException nsae) {
      log.error("SHA1 algorithm not supported", nsae);
    }
    // log.trace("<generateSHA1Fingerprint");
    return null;
  } // generateSHA1Fingerprint

  /**
   * Generate a MD5 fingerprint from a byte array containing a certificate
   *
   * @param ba Byte array containing DER encoded Certificate.
   *
   * @return Byte array containing MD5 hash of DER encoded certificate (raw binary hash).
   */
  public static byte[] generateMD5Fingerprint(byte[] ba) {
    try {
      MessageDigest md = MessageDigest.getInstance("MD5");

      return md.digest(ba);
    } catch (NoSuchAlgorithmException nsae) {
      log.error("MD5 algorithm not supported", nsae);
    }

    return null;
  } // generateMD5Fingerprint

  /**
   * Converts Sun Key usage bits to Bouncy castle key usage kits
   *
   * @param sku key usage bit fields according to java.security.cert.X509Certificate#getKeyUsage, must be a boolean aray of size 9.
   * @return key usage int according to org.bouncycastle.jce.X509KeyUsage#X509KeyUsage, or -1 if input is null.
   * @see java.security.cert.X509Certificate#getKeyUsage
   * @see org.bouncycastle.jce.X509KeyUsage#X509KeyUsage
   */
  public static int sunKeyUsageToBC(boolean[] sku) {
    if (sku == null) {
      return -1;
    }
    int bcku = 0;
    if (sku[0]) {
      bcku = bcku | X509KeyUsage.digitalSignature;
    }
    if (sku[1]) {
      bcku = bcku | X509KeyUsage.nonRepudiation;
    }
    if (sku[2]) {
      bcku = bcku | X509KeyUsage.keyEncipherment;
    }
    if (sku[3]) {
      bcku = bcku | X509KeyUsage.dataEncipherment;
    }
    if (sku[4]) {
      bcku = bcku | X509KeyUsage.keyAgreement;
    }
    if (sku[5]) {
      bcku = bcku | X509KeyUsage.keyCertSign;
    }
    if (sku[6]) {
      bcku = bcku | X509KeyUsage.cRLSign;
    }
    if (sku[7]) {
      bcku = bcku | X509KeyUsage.encipherOnly;
    }
    if (sku[8]) {
      bcku = bcku | X509KeyUsage.decipherOnly;
    }
    return bcku;
  }

  /**
   * Converts DERBitString ResonFlags to a RevokedCertInfo constant
   *
   * @param reasonFlags DERBITString received from org.bouncycastle.asn1.x509.ReasonFlags.
   * @return int according to org.cesecore.certificates.crl.RevokedCertInfo
   */
  public static int bitStringToRevokedCertInfo(DERBitString reasonFlags) {
    int ret = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
    if (reasonFlags == null) {
      return ret;
    }
    int val = reasonFlags.intValue();
    if (log.isDebugEnabled()) {
      log.debug("Int value of bitString revocation reason: " + val);
    }
    if ((val & ReasonFlags.aACompromise) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE;
    }
    if ((val & ReasonFlags.affiliationChanged) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED;
    }
    if ((val & ReasonFlags.cACompromise) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE;
    }
    if ((val & ReasonFlags.certificateHold) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD;
    }
    if ((val & ReasonFlags.cessationOfOperation) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION;
    }
    if ((val & ReasonFlags.keyCompromise) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE;
    }
    if ((val & ReasonFlags.privilegeWithdrawn) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN;
    }
    if ((val & ReasonFlags.superseded) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_SUPERSEDED;
    }
    if ((val & ReasonFlags.unused) != 0) {
      ret = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;
    }
    return ret;
  }

  /**
   * Method used to insert a CN postfix into DN by extracting the first found CN appending cnpostfix and then replacing the original CN with the new
   * one in DN.
   *
   * If no CN could be found in DN then should the given DN be returned untouched
   *
   * @param dn the DN to manipulate, cannot be null
   * @param cnpostfix the postfix to insert, cannot be null
   * @return the new DN
   */
  public static String insertCNPostfix(String dn, String cnpostfix) {
    String newdn = null;

    if ((dn != null) && (cnpostfix != null)) {
      String o;
      X509NameTokenizer xt = new X509NameTokenizer(dn);
      boolean alreadyreplaced = false;
      while (xt.hasMoreTokens()) {
        o = xt.nextToken();
        if (
          !alreadyreplaced &&
          (o.length() > 3) &&
          o.substring(0, 3).equalsIgnoreCase("cn=")
        ) {
          o += cnpostfix;
          alreadyreplaced = true;
        }
        if (newdn == null) {
          newdn = o;
        } else {
          newdn += "," + o;
        }
      }
    }

    return newdn;
  } // insertCNPostfix

  /**
   * class for breaking up an X500 Name into it's component tokens, ala java.util.StringTokenizer. Taken from BouncyCastle, but does NOT use or
   * consider escaped characters. Used for reversing DNs without unescaping.
   */
  private static class BasicX509NameTokenizer {

    private final String oid;
    private int index = -1;
    /*
     * Since this class isn't thread safe anyway, we can use the slightly faster StringBuilder instead of StringBuffer
     */
    private StringBuilder buf = new StringBuilder();

    public BasicX509NameTokenizer(String oid) {
      this.oid = oid;
    }

    public boolean hasMoreTokens() {
      return (index != oid.length());
    }

    public String nextToken() {
      if (index == oid.length()) {
        return null;
      }

      int end = index + 1;
      boolean quoted = false;
      boolean escaped = false;

      buf.setLength(0);

      while (end != oid.length()) {
        char c = oid.charAt(end);

        if (c == '"') {
          if (!escaped) {
            buf.append(c);
            quoted ^= true; // Faster than "quoted = !quoted;"
          } else {
            buf.append(c);
          }
          escaped = false;
        } else {
          if (escaped || quoted) {
            buf.append(c);
            escaped = false;
          } else if (c == '\\') {
            buf.append(c);
            escaped = true;
          } else if ((c == ',') && (!escaped)) {
            break;
          } else {
            buf.append(c);
          }
        }
        end++;
      }

      index = end;
      return buf.toString().trim();
    }
  } // BasicX509NameTokenizer

  /**
   * Obtains a List with the DERObjectIdentifiers for dNObjects names, in the specified order
   *
   * @param ldaporder if true the returned order are as defined in LDAP RFC (CN=foo,O=bar,C=SE), otherwise the order is a defined in X.500
   *            (C=SE,O=bar,CN=foo).
   * @return a List with DERObjectIdentifiers defining the known order we require
   * @see org.cesecore.certificates.util.DnComponents#getDnObjects(boolean)
   */
  public static List<DERObjectIdentifier> getX509FieldOrder(boolean ldaporder) {
    List<DERObjectIdentifier> fieldOrder = new ArrayList<DERObjectIdentifier>();
    for (final String dNObject : DnComponents.getDnObjects(ldaporder)) {
      fieldOrder.add(DnComponents.getOid(dNObject));
    }
    return fieldOrder;
  }

  /**
   * Obtain a X509Name reordered, if some fields from original X509Name doesn't appear in "ordering" parameter, they will be added at end in the
   * original order.
   *
   * @param x509Name the X509Name that is unordered
   * @param ldaporder true if LDAP ordering of DN should be used (default in EJBCA), false for X.500 order, ldap order is CN=A,OU=B,O=C,C=SE, x.500
   *            order is the reverse
   * @return X509Name with ordered conmponents according to the orcering vector
   */
  private static X509Name getOrderedX509Name(
    final X509Name x509Name,
    boolean ldaporder,
    final X509NameEntryConverter converter
  ) {
    // -- Null prevent
    // Guess order of the input name
    final boolean isLdapOrder = !isDNReversed(x509Name.toString());
    // -- New order for the X509 Fields
    final List<DERObjectIdentifier> newOrdering = new ArrayList<
      DERObjectIdentifier
    >();
    final List<Object> newValues = new ArrayList<Object>();
    // -- Add ordered fields
    @SuppressWarnings("unchecked")
    final Vector<DERObjectIdentifier> allOids = x509Name.getOIDs();
    // If we think the DN is in LDAP order, first order it as a LDAP DN, if we don't think it's LDAP order
    // order it as a X.500 DN
    final List<DERObjectIdentifier> ordering = getX509FieldOrder(isLdapOrder);
    final HashSet<DERObjectIdentifier> hs = new HashSet<DERObjectIdentifier>(
      allOids.size() + ordering.size()
    );
    for (final DERObjectIdentifier oid : ordering) {
      if (!hs.contains(oid)) {
        hs.add(oid);
        @SuppressWarnings("unchecked")
        final Vector<Object> valueList = x509Name.getValues(oid);
        // -- Only add the OID if has not null value
        for (final Object value : valueList) {
          newOrdering.add(oid);
          newValues.add(value);
        }
      }
    }
    // -- Add unexpected fields to the end
    for (final DERObjectIdentifier oid : allOids) {
      if (!hs.contains(oid)) {
        hs.add(oid);
        @SuppressWarnings("unchecked")
        final Vector<Object> valueList = x509Name.getValues(oid);
        // -- Only add the OID if has not null value
        for (final Object value : valueList) {
          newOrdering.add(oid);
          newValues.add(value);
          if (log.isDebugEnabled()) {
            log.debug("added --> " + oid + " val: " + value);
          }
        }
      }
    }
    // If the requested ordering was the reverse of the ordering the input string was in (by our guess in the beginning)
    // we have to reverse the vectors
    if (ldaporder != isLdapOrder) {
      if (log.isDebugEnabled()) {
        log.debug(
          "Reversing order of DN, ldaporder=" +
          ldaporder +
          ", isLdapOrder=" +
          isLdapOrder
        );
      }
      Collections.reverse(newOrdering);
      Collections.reverse(newValues);
    }
    // -- Return X509Name with the ordered fields
    return new X509Name(
      new Vector<DERObjectIdentifier>(newOrdering),
      new Vector<Object>(newValues),
      converter
    );
  } //

  /**
   * Obtain the directory string for the directoryName generation form the Subject Alternative Name String.
   *
   * @param altName
   * @return
   */
  private static String getDirectoryStringFromAltName(String altName) {
    String directoryName = CertTools1.getPartFromDN(
      altName,
      CertTools1.DIRECTORYNAME
    );
    // DNFieldExtractor dnfe = new DNFieldExtractor(altName, DNFieldExtractor.TYPE_SUBJECTALTNAME);
    // String directoryName = dnfe.getField(DNFieldExtractor.DIRECTORYNAME, 0);
    /** TODO: Validate or restrict the directoryName Fields? */
    return ("".equals(directoryName) ? null : directoryName);
  } // getDirectoryStringFromAltName

  /**
   * Method to create certificate path and to check it's validity from a list of certificates. The list of certificates should only contain one root
   * certificate.
   *
   * @param certlist
   * @return the certificatepath with the root CA at the end
   * @throws CertPathValidatorException if the certificate chain can not be constructed
   * @throws InvalidAlgorithmParameterException
   * @throws NoSuchProviderException
   * @throws NoSuchAlgorithmException
   * @throws CertificateException
   */
  public static Collection<Certificate> createCertChain(
    Collection<?> certlistin
  )
    throws CertPathValidatorException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException {
    ArrayList<Certificate> returnval = new ArrayList<Certificate>();

    Collection<Certificate> certlist = orderCertificateChain(certlistin);

    // set certificate chain
    Certificate rootcert = null;
    ArrayList<Certificate> calist = new ArrayList<Certificate>();
    Iterator<Certificate> iter = certlist.iterator();
    while (iter.hasNext()) {
      Certificate next = iter.next();
      if (CertTools1.isSelfSigned(next)) {
        rootcert = next;
      } else {
        calist.add(next);
      }
    }

    if (calist.isEmpty()) {
      // only one root cert, no certchain
      returnval.add(rootcert);
    } else {
      // We need a bit special handling for CV certificates because those can not be handled using a PKIX CertPathValidator
      Certificate test = calist.get(0);
      if (test.getType().equals("CVC")) {
        if (calist.size() == 1) {
          returnval.add(test);
          returnval.add(rootcert);
        } else {
          throw new CertPathValidatorException(
            "CVC certificate chain can not be of length longer than two."
          );
        }
      } else {
        // Normal X509 certificates
        HashSet<TrustAnchor> trustancors = new HashSet<TrustAnchor>();
        TrustAnchor trustanchor = null;
        trustanchor = new TrustAnchor((X509Certificate) rootcert, null);
        trustancors.add(trustanchor);

        // Create the parameters for the validator
        PKIXParameters params = new PKIXParameters(trustancors);

        // Disable CRL checking since we are not supplying any CRLs
        params.setRevocationEnabled(false);
        params.setDate(new Date());

        // Create the validator and validate the path
        CertPathValidator certPathValidator = CertPathValidator.getInstance(
          CertPathValidator.getDefaultType(),
          "BC"
        );
        CertificateFactory fact = CertTools1.getCertificateFactory();
        CertPath certpath = fact.generateCertPath(calist);

        CertPathValidatorResult result = certPathValidator.validate(
          certpath,
          params
        );

        // Get the certificates validate in the path
        PKIXCertPathValidatorResult pkixResult =
          (PKIXCertPathValidatorResult) result;
        returnval.addAll(certpath.getCertificates());

        // Get the CA used to validate this path
        TrustAnchor ta = pkixResult.getTrustAnchor();
        X509Certificate cert = ta.getTrustedCert();
        returnval.add(cert);
      }
    }
    return returnval;
  } // createCertChain

  /**
   * Method ordering a list of certificate into a certificate path with the root CA at the end. Does not check validity or verification of any kind,
   * just ordering by issuerdn.
   *
   * @param certlist list of certificates to order can be collection of Certificate or byte[] (der encoded certs).
   * @return Collection with certificatechain.
   */
  private static Collection<Certificate> orderCertificateChain(
    Collection<?> certlist
  ) throws CertPathValidatorException {
    ArrayList<Certificate> returnval = new ArrayList<Certificate>();
    Certificate rootca = null;
    HashMap<String, Certificate> cacertmap = new HashMap<String, Certificate>();
    Iterator<?> iter = certlist.iterator();
    while (iter.hasNext()) {
      Certificate cert = null;
      Object o = iter.next();
      try {
        cert = (Certificate) o;
      } catch (ClassCastException e) {
        // This was not a certificate, is it byte encoded?
        byte[] certBytes = (byte[]) o;
        try {
          cert = CertTools1.getCertfromByteArray(certBytes);
        } catch (CertificateException e1) {
          throw new CertPathValidatorException(e1);
        }
      }
      if (CertTools1.isSelfSigned(cert)) {
        rootca = cert;
      } else {
        log.debug(
          "Adding to cacertmap with index '" +
          CertTools1.getIssuerDN(cert) +
          "'"
        );
        cacertmap.put(CertTools1.getIssuerDN(cert), cert);
      }
    }

    if (rootca == null) {
      throw new CertPathValidatorException(
        "No root CA certificate found in certificatelist"
      );
    }
    returnval.add(0, rootca);
    Certificate currentcert = rootca;
    int i = 0;
    while (certlist.size() != returnval.size() && i <= certlist.size()) {
      log.debug(
        "Looking in cacertmap for '" +
        CertTools1.getSubjectDN(currentcert) +
        "'"
      );
      Certificate nextcert = (Certificate) cacertmap.get(
        CertTools1.getSubjectDN(currentcert)
      );
      if (nextcert == null) {
        throw new CertPathValidatorException("Error building certificate path");
      }
      returnval.add(0, nextcert);
      currentcert = nextcert;
      i++;
    }

    if (i > certlist.size()) {
      throw new CertPathValidatorException("Error building certificate path");
    }

    return returnval;
  } // orderCertificateChain

  /**
   * @return true if the chains are nonempty, contain the same certificates in the same order
   */
  public static boolean compareCertificateChains(
    Certificate[] chainA,
    Certificate[] chainB
  ) {
    if (chainA == null || chainB == null) {
      return false;
    }
    if (chainA.length != chainB.length) {
      return false;
    }
    for (int i = 0; i < chainA.length; i++) {
      if (chainA[i] == null || !chainA[i].equals(chainB[i])) {
        return false;
      }
    }
    return true;
  }

  /**
   * Dumps a certificate (cvc or x.509) to string format, suitable for manual inspection/debugging.
   *
   * @param cert Certificate
   *
   * @return String with cvc or asn.1 dump.
   */
  public static String dumpCertificateAsString(final Certificate cert) {
    String ret = null;
    if (cert instanceof X509Certificate) {
      try {
        final Certificate c = getCertfromByteArray(cert.getEncoded());
        ret = c.toString();
        // ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(cert.getEncoded()));
        // DERObject obj = ais.readObject();
        // ret = ASN1Dump.dumpAsString(obj);
      } catch (CertificateException e) {
        ret = e.getMessage();
      }
    } else if (StringUtils.equals(cert.getType(), "CVC")) {
      final CardVerifiableCertificate cvccert =
        (CardVerifiableCertificate) cert;
      final CVCObject obj = cvccert.getCVCertificate();
      ret = obj.getAsText("");
    } else {
      throw new IllegalArgumentException(
        "dumpCertificateAsString: Certificate of type " +
        cert.getType() +
        " is not implemented"
      );
    }
    return ret;
  }
}

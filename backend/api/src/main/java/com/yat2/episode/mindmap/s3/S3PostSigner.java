package com.yat2.episode.mindmap.s3;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.yat2.episode.global.exception.CustomException;
import com.yat2.episode.global.exception.ErrorCode;
import com.yat2.episode.mindmap.s3.dto.S3UploadFieldsDto;
import com.yat2.episode.mindmap.s3.dto.S3UploadResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Component
@RequiredArgsConstructor
public class S3PostSigner {
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private static final ObjectMapper compactMapper = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_NULL)
            .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);

    private final S3Properties s3Properties;

    public S3UploadResponseDto generatePostFields(String bucket, String key, String region, String endpoint,
                                                  AwsCredentials credentials) {

        String accessKey = credentials.accessKeyId();
        String secretKey = credentials.secretAccessKey();
        String sessionToken = (credentials instanceof AwsSessionCredentials)
                              ? ((AwsSessionCredentials) credentials).sessionToken() : null;

        ZonedDateTime now = ZonedDateTime.now(ZoneId.of("UTC")).truncatedTo(ChronoUnit.SECONDS);

        String dateStamp = now.format(DateTimeFormatter.ofPattern("yyyyMMdd"));
        String xAmzDate = now.format(DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'"));

        String expiration = now.plusMinutes(15).format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'"));

        String credential = accessKey + "/" + dateStamp + "/" + region + "/s3/aws4_request";

        String policyJson = createPolicyJson(bucket, key, credential, xAmzDate, sessionToken, expiration);

        String policyBase64 = Base64.getEncoder().encodeToString(policyJson.getBytes(StandardCharsets.UTF_8));

        String signature = calculateSignature(policyBase64, secretKey, dateStamp, region);

        String actionUrl = (endpoint != null && !endpoint.isEmpty()) ? endpoint + "/" + bucket :
                           "https://" + bucket + ".s3." + region + ".amazonaws.com";

        S3UploadFieldsDto fields = new S3UploadFieldsDto(
                key,
                "AWS4-HMAC-SHA256",
                credential,
                xAmzDate,
                sessionToken,
                policyBase64,
                signature
        );

        return new S3UploadResponseDto(actionUrl, fields);
    }

    private String createPolicyJson(String bucket, String key, String credential, String xAmzDate, String sessionToken,
                                    String expiration) {
        try {
            Map<String, Object> policy = new LinkedHashMap<>();
            policy.put("expiration", expiration);

            List<Object> conditions = new ArrayList<>();
            conditions.add(Map.of("bucket", bucket));
            conditions.add(Map.of("key", key));
            conditions.add(Map.of("x-amz-algorithm", "AWS4-HMAC-SHA256"));
            conditions.add(Map.of("x-amz-credential", credential));
            conditions.add(Map.of("x-amz-date", xAmzDate));

            if (sessionToken != null && !sessionToken.isEmpty()) {
                conditions.add(Map.of("x-amz-security-token", sessionToken));
            }

            conditions.add(List.of("content-length-range", 0, s3Properties.getMaxUploadSize()));

            policy.put("conditions", conditions);

            return compactMapper.writeValueAsString(policy);
        } catch (JsonProcessingException e) {
            throw new CustomException(ErrorCode.S3_URL_FAIL);
        }
    }

    private String calculateSignature(String stringToSign, String secret, String dateStamp, String region) {
        try {
            byte[] kSecret = ("AWS4" + secret).getBytes(StandardCharsets.UTF_8);
            byte[] kDate = hmac(kSecret, dateStamp);
            byte[] kRegion = hmac(kDate, region);
            byte[] kService = hmac(kRegion, "s3");
            byte[] kSigning = hmac(kService, "aws4_request");
            return toHex(hmac(kSigning, stringToSign));
        } catch (Exception e) {
            throw new CustomException(ErrorCode.S3_URL_FAIL);
        }
    }

    private byte[] hmac(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
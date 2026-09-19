package com.trustshield.deepfake.forensics;

import com.drew.imaging.ImageMetadataReader;
import com.drew.metadata.Directory;
import com.drew.metadata.Metadata;
import com.drew.metadata.exif.ExifIFD0Directory;
import com.drew.metadata.exif.ExifSubIFDDirectory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Locale;

/**
 * EXIF and metadata provenance analyzer using Drew Noakes' metadata-extractor 2.19.0.
 *
 * <p>Inspects embedded photographic provenance records: Camera Make, Model,
 * Software tag, and DateTimeOriginal. Identifies manipulation traces and software tags
 * associated with synthetic generators (e.g. Midjourney, Stable Diffusion, DALL-E) or
 * desktop editors (e.g. Photoshop, GIMP).
 */
@Component
public class ExifProvenanceAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(ExifProvenanceAnalyzer.class);

    private static final List<String> MANIPULATION_SOFTWARE_KEYWORDS = List.of(
            "photoshop", "gimp", "lightroom", "canva", "affinity",
            "stable diffusion", "midjourney", "dall-e", "comfyui", "automatic1111",
            "novelai", "invokeai", "generative fill", "firefly"
    );

    public record ExifResult(
            boolean hasExif,
            String cameraModel,
            String software,
            String dateTimeOriginal,
            boolean metadataInconsistent,
            String detail
    ) {}

    /**
     * Extracts and inspects EXIF provenance from raw image bytes.
     *
     * @param rawBytes image bytes
     * @return ExifResult containing hardware details, software tags, and inconsistency flags
     */
    public ExifResult analyze(byte[] rawBytes) {
        if (rawBytes == null || rawBytes.length < 4) {
            return new ExifResult(false, null, null, null, false, "Image payload too small for metadata extraction");
        }

        try {
            Metadata metadata = ImageMetadataReader.readMetadata(new ByteArrayInputStream(rawBytes));

            ExifIFD0Directory ifd0 = metadata.getFirstDirectoryOfType(ExifIFD0Directory.class);
            ExifSubIFDDirectory subIfd = metadata.getFirstDirectoryOfType(ExifSubIFDDirectory.class);

            boolean hasExif = (ifd0 != null || subIfd != null);

            String make = ifd0 != null ? ifd0.getString(ExifIFD0Directory.TAG_MAKE) : null;
            String model = ifd0 != null ? ifd0.getString(ExifIFD0Directory.TAG_MODEL) : null;
            String software = ifd0 != null ? ifd0.getString(ExifIFD0Directory.TAG_SOFTWARE) : null;
            String dateTime = subIfd != null ? subIfd.getString(ExifSubIFDDirectory.TAG_DATETIME_ORIGINAL) : null;

            String cameraModel = null;
            if (make != null && model != null) {
                cameraModel = make.trim() + " " + model.trim();
            } else if (model != null) {
                cameraModel = model.trim();
            } else if (make != null) {
                cameraModel = make.trim();
            }

            boolean inconsistent = false;
            StringBuilder detail = new StringBuilder();

            if (!hasExif) {
                detail.append("No EXIF metadata present (metadata stripped or non-camera origin). ");
            } else {
                detail.append(String.format("EXIF present. Camera: %s. ", cameraModel != null ? cameraModel : "Unknown"));
            }

            if (software != null && !software.isBlank()) {
                String swLower = software.toLowerCase(Locale.ROOT);
                boolean foundSuspicious = MANIPULATION_SOFTWARE_KEYWORDS.stream().anyMatch(swLower::contains);
                if (foundSuspicious) {
                    inconsistent = true;
                    detail.append(String.format("Software signature '%s' indicates editing suite or synthetic media generation. ", software));
                } else {
                    detail.append(String.format("Software tag: %s. ", software));
                }
            }

            if (dateTime != null) {
                detail.append(String.format("Captured at: %s. ", dateTime));
            }

            return new ExifResult(
                    hasExif,
                    cameraModel,
                    software,
                    dateTime,
                    inconsistent,
                    detail.toString().trim()
            );

        } catch (Exception e) {
            log.debug("No EXIF metadata parsed: {}", e.getMessage());
            return new ExifResult(false, null, null, null, false, "EXIF metadata absent or unreadable: " + e.getMessage());
        }
    }
}

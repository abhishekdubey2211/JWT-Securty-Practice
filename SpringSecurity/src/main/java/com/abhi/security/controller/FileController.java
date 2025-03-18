package com.abhi.security.controller;

import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.file.*;

@RestController
@RequestMapping("/api/file")
public class FileController {

	private static final int MAX_RETRIES = 3;
	private static final int BUFFER_SIZE = 16 * 1024 * 1024; // 16MB
	private static final long LARGE_FILE_THRESHOLD = 100 * 1024 * 1024; // 100MB

	@PostMapping("/upload")
	public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file, @RequestParam String filePath) {
		try {
			long fileSize = file.getSize();
			Path directoryPath = Paths.get(filePath);

			Files.createDirectories(directoryPath);

			String originalFilename = file.getOriginalFilename();
			if (originalFilename == null || originalFilename.trim().isEmpty()) {
				return ResponseEntity.badRequest().body("Invalid file name.");
			}

			String sanitizedFileName = originalFilename.replaceAll("\\s+", "_");
			Path destinationPath = directoryPath.resolve(sanitizedFileName);

			Path savedFilePath = (fileSize > LARGE_FILE_THRESHOLD) ? storeLargeFile(file, destinationPath)
					: storeFile(file, destinationPath);

			return ResponseEntity.ok("File uploaded successfully: " + savedFilePath.toAbsolutePath());
		} catch (IOException e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("File upload failed: " + e.getMessage());
		}
	}

	private Path storeFile(MultipartFile file, Path destinationPath) throws IOException {
		for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
			try (InputStream inputStream = file.getInputStream()) {
				Files.copy(inputStream, destinationPath, StandardCopyOption.REPLACE_EXISTING);
				return destinationPath;
			} catch (IOException e) {
				if (attempt == MAX_RETRIES) {
					throw new IOException("Upload failed after " + MAX_RETRIES + " attempts.", e);
				}
			}
		}
		throw new IOException("Unknown upload error.");
	}

	private Path storeLargeFile(MultipartFile file, Path destinationPath) throws IOException {
		Files.createDirectories(destinationPath.getParent()); // Ensure parent directory exists

		for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
			try (InputStream inputStream = file.getInputStream();
					OutputStream outputStream = Files.newOutputStream(destinationPath, StandardOpenOption.CREATE,
							StandardOpenOption.TRUNCATE_EXISTING)) {

				byte[] buffer = new byte[BUFFER_SIZE];
				int bytesRead;
				while ((bytesRead = inputStream.read(buffer)) != -1) {
					outputStream.write(buffer, 0, bytesRead);
				}
				outputStream.flush();

				return destinationPath;
			} catch (IOException e) {
				if (attempt == MAX_RETRIES) {
					throw new IOException("Upload failed after " + MAX_RETRIES + " attempts.", e);
				}
			}
		}
		throw new IOException("Unknown upload error.");
	}

	@GetMapping("/copy")
	public ResponseEntity<String> copyFile(@RequestParam String sourcePath, @RequestParam String destinationPath) {
		Path source = Paths.get(sourcePath);
		Path destination = Paths.get(destinationPath);

		if (Files.notExists(source)) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND)
					.body("Source file does not exist: " + source.toAbsolutePath());
		}

		try {
			Files.createDirectories(destination.getParent());

			try (InputStream inputStream = Files.newInputStream(source);
					OutputStream outputStream = Files.newOutputStream(destination, StandardOpenOption.CREATE,
							StandardOpenOption.TRUNCATE_EXISTING)) {

				byte[] buffer = new byte[BUFFER_SIZE];
				int bytesRead;
				while ((bytesRead = inputStream.read(buffer)) != -1) {
					outputStream.write(buffer, 0, bytesRead);
				}
				outputStream.flush();
			}

			return ResponseEntity.ok("File copied successfully to: " + destination.toAbsolutePath());
		} catch (IOException e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("File copy failed: " + e.getMessage());
		}
	}

	@GetMapping("/download/url")
	public ResponseEntity<String> downloadFileFromUrl(@RequestParam String fileUrl, @RequestParam String storagePath) {
		Path outputPath = Paths.get(storagePath);

		if (outputPath.getParent() != null) {
			try {
				Files.createDirectories(outputPath.getParent());
			} catch (IOException e) {
				return ResponseEntity.internalServerError().body("Failed to create directories: " + e.getMessage());
			}
		}

		for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
			try {
				downloadFile(fileUrl, outputPath);
				return ResponseEntity.ok("File downloaded successfully: " + outputPath.toAbsolutePath());
			} catch (IOException e) {
				if (attempt == MAX_RETRIES) {
					return ResponseEntity.internalServerError()
							.body("Failed to download after " + MAX_RETRIES + " attempts. Error: " + e.getMessage());
				}
			}
		}
		return ResponseEntity.internalServerError().body("Unknown error occurred.");
	}

	private void downloadFile(String fileUrl, Path outputPath) throws IOException {
	    URL url = URI.create(fileUrl).toURL(); // Use URI first, then convert to URL
		HttpURLConnection connection = (HttpURLConnection) url.openConnection();
		connection.setRequestMethod("GET");
		connection.setConnectTimeout(10_000);
		connection.setReadTimeout(60_000);
		connection.setRequestProperty("User-Agent", "Mozilla/5.0");

		try (InputStream in = new BufferedInputStream(connection.getInputStream(), BUFFER_SIZE);
				OutputStream out = Files.newOutputStream(outputPath)) {

			byte[] buffer = new byte[BUFFER_SIZE];
			int bytesRead;
			while ((bytesRead = in.read(buffer)) != -1) {
				out.write(buffer, 0, bytesRead);
			}
		} finally {
			connection.disconnect(); // Ensure the connection is closed
		}
	}

}

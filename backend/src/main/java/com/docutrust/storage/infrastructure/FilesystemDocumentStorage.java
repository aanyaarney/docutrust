package com.docutrust.storage.infrastructure;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import com.docutrust.storage.domain.DocumentStorage;
import com.docutrust.storage.domain.StorageException;

/**
 * Stores documents on the local filesystem.
 *
 * <p>Lets the full application run without Docker or an object store, which
 * keeps local development and CI fast. Production uses
 * {@code MinioDocumentStorage} or another object store behind the same
 * interface.
 *
 * <h2>Path traversal</h2>
 * Storage keys are composed by the application, never taken raw from user
 * input, but this class still validates that every resolved path stays inside
 * the configured root. A key containing {@code ../} must not be able to write
 * outside the storage directory — defence in depth against a future caller that
 * forwards a user-supplied name.
 */
public class FilesystemDocumentStorage implements DocumentStorage {

    private final Path root;

    public FilesystemDocumentStorage(Path root) {
        this.root = root.toAbsolutePath().normalize();
        try {
            Files.createDirectories(this.root);
        } catch (IOException e) {
            throw new StorageException("Could not create the document storage directory", e);
        }
    }

    @Override
    public void store(String key, InputStream content, String contentType, long sizeBytes) {
        Path target = resolve(key);
        try {
            Files.createDirectories(target.getParent());
            Files.copy(content, target, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new StorageException("Failed to store document content", e);
        }
    }

    @Override
    public InputStream retrieve(String key) {
        Path source = resolve(key);
        if (!Files.exists(source)) {
            throw new StorageException("No stored content found for the requested document");
        }
        try {
            return Files.newInputStream(source);
        } catch (IOException e) {
            throw new StorageException("Failed to read stored document content", e);
        }
    }

    @Override
    public byte[] retrieveAllBytes(String key) {
        try (InputStream in = retrieve(key)) {
            return in.readAllBytes();
        } catch (IOException e) {
            throw new StorageException("Failed to read stored document content", e);
        }
    }

    @Override
    public boolean exists(String key) {
        return Files.exists(resolve(key));
    }

    @Override
    public void delete(String key) {
        try {
            Files.deleteIfExists(resolve(key));
        } catch (IOException e) {
            throw new StorageException("Failed to delete stored document content", e);
        }
    }

    @Override
    public String backendName() {
        return "filesystem";
    }

    /** Resolves a key under the root, refusing anything that escapes it. */
    private Path resolve(String key) {
        Path resolved = root.resolve(key).normalize();
        if (!resolved.startsWith(root)) {
            // Never echo the attempted path back; that would confirm filesystem
            // layout to a caller probing for traversal.
            throw new StorageException("Rejected a storage key that resolves outside the storage root");
        }
        return resolved;
    }
}

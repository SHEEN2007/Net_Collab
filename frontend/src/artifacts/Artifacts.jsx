
import React, { useEffect, useState } from "react";
import api from "../api";

import {
  generateRSAKeyPair,
  exportPublicKeyPem,
  exportPrivateKeyPem,
  importPrivateKeyPem,
  importPublicKeyPem,
  unwrapAESKey,
  wrapAESKey,
  decryptArtifact,
  calculateSHA256,
} from "../artifactCrypto";

// Convert binary data to Base64.
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  let binary = "";

  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(
      ...bytes.subarray(i, i + chunkSize)
    );
  }

  return window.btoa(binary);
}

// Decode a Base64 UTF-8 filename.
function decodeBase64Filename(value) {
  if (!value) return "download";

  try {
    const binary = window.atob(value);
    const bytes = Uint8Array.from(
      binary,
      (char) => char.charCodeAt(0)
    );

    return new TextDecoder().decode(bytes);
  } catch {
    return "download";
  }
}

// Trigger a browser download.
function saveFile(data, filename) {
  const blob = new Blob([data]);
  const url = window.URL.createObjectURL(blob);

  const link = document.createElement("a");
  link.href = url;
  link.download = filename;

  document.body.appendChild(link);
  link.click();
  link.remove();

  window.setTimeout(() => {
    window.URL.revokeObjectURL(url);
  }, 1000);
}

// Extract readable errors, including arraybuffer API errors.
async function getApiError(err) {
  const data = err.response?.data;

  if (data instanceof ArrayBuffer) {
    try {
      const text = new TextDecoder().decode(data);
      const parsed = JSON.parse(text);
      return parsed.error || parsed.detail || text;
    } catch {
      return "The server returned an unreadable error.";
    }
  }

  if (data instanceof Blob) {
    try {
      const text = await data.text();
      const parsed = JSON.parse(text);
      return parsed.error || parsed.detail || text;
    } catch {
      return "The server returned an unreadable error.";
    }
  }

  return (
    data?.error ||
    data?.detail ||
    err.message ||
    "An unexpected error occurred."
  );
}

export default function Artifacts() {
  const [projects, setProjects] = useState([]);
  const [artifacts, setArtifacts] = useState([]);
  const [versionHistories, setVersionHistories] = useState({});
  const [expandedVersionArtifact, setExpandedVersionArtifact] = useState(null);
  const [loadingVersions, setLoadingVersions] = useState(false);

  const [selectedProject, setSelectedProject] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [description, setDescription] = useState("");

  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [versionUploading, setVersionUploading] = useState(false);
  const [versionUploadArtifact, setVersionUploadArtifact] = useState(null);
  const [versionFile, setVersionFile] = useState(null);
  const [downloadingId, setDownloadingId] = useState(null);

  const [privateKey, setPrivateKey] = useState(null);
  const [keyStatus, setKeyStatus] = useState("");
  const [generatingKey, setGeneratingKey] = useState(false);

  const [sharingArtifact, setSharingArtifact] = useState(null);
  const [recipientUsername, setRecipientUsername] = useState("");
  const [sharePermission, setSharePermission] = useState("view");
  const [sharing, setSharing] = useState(false);
  const [accessArtifact, setAccessArtifact] = useState(null);
  const [artifactRecipients, setArtifactRecipients] = useState([]);
  const [loadingRecipients, setLoadingRecipients] = useState(false);
  const [revokingUserId, setRevokingUserId] = useState(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    loadProjects();
    loadArtifacts();
  }, []);

  // ------------------------------------------
  // LOAD PROJECTS
  // ------------------------------------------

  const loadProjects = async () => {
    try {
      const response = await api.get("/projects/");

      const data = Array.isArray(response.data)
        ? response.data
        : response.data.results || [];

      setProjects(data);
    } catch (err) {
      console.error("Project loading failed:", err);
      setError("Unable to load projects.");
    }
  };

  // ------------------------------------------
  // LOAD ARTIFACTS
  // ------------------------------------------

  const loadArtifacts = async () => {
    try {
      const response = await api.get("/artifacts/");

      const data = Array.isArray(response.data)
        ? response.data
        : response.data.results || [];

      setArtifacts(data);
    } catch (err) {
      console.error("Artifact loading failed:", err);
      setError("Unable to load artifacts.");
    } finally {
      setLoading(false);
    }
  };
  // ------------------------------------------
  // LOAD ARTIFACT VERSION HISTORY
  // ------------------------------------------

  const handleViewVersions = async (artifact) => {
    if (expandedVersionArtifact === artifact.id) {
      setExpandedVersionArtifact(null);
      return;
    }

    try {
      setLoadingVersions(true);
      setError("");

      const response = await api.get(
        `/artifacts/${artifact.id}/versions/`
      );

      setVersionHistories((previous) => ({
        ...previous,
        [artifact.id]: response.data.versions || [],
      }));

      setExpandedVersionArtifact(artifact.id);
    } catch (err) {
      console.error("Version history loading failed:", err);
      setError(await getApiError(err));
    } finally {
      setLoadingVersions(false);
    }
  };

 // ------------------------------------------
 // GENERATE AND REGISTER RSA KEY PAIR
 // ------------------------------------------


const handleGenerateAndRegisterKey = async () => {
  const confirmed = window.confirm(
    "This will replace your currently registered RSA public key. " +
    "Older encrypted artifacts may require their original private keys. " +
    "Do you have your existing private keys safely backed up? Continue?"
  );

  if (!confirmed) return;

  try {
    setGeneratingKey(true);
    setError("");
    setMessage("");
    setKeyStatus("Generating RSA-2048 key pair...");

    const keyPair = await generateRSAKeyPair();

    const publicKeyPem = await exportPublicKeyPem(
      keyPair.publicKey
    );

    const privateKeyPem = await exportPrivateKeyPem(
      keyPair.privateKey
    );

    const response = await api.post(
      "/accounts/public-key/",
      { public_key: publicKeyPem }
    );

    setPrivateKey(keyPair.privateKey);

    saveFile(
      privateKeyPem,
      "netcollab-private-key.pem"
    );

    setKeyStatus("RSA key pair generated and registered successfully.");

    setMessage(
      `Public key registered. Fingerprint: ${response.data.key_fingerprint}`
    );
  } catch (err) {
    console.error("RSA registration failed:", err);
    setKeyStatus("");
    setError(await getApiError(err));
  } finally {
    setGeneratingKey(false);
  }
};

  // ------------------------------------------
  // IMPORT PRIVATE KEY
  // ------------------------------------------

  const handlePrivateKeyUpload = async (event) => {
    const file = event.target.files?.[0];

    if (!file) return;

    if (!file.name.toLowerCase().endsWith(".pem")) {
      setPrivateKey(null);
      setKeyStatus("");
      setError("Please select a valid .pem private key file.");
      event.target.value = "";
      return;
    }

    try {
      setError("");
      setKeyStatus("Importing private key...");

      const pem = await file.text();

      if (!pem.includes("-----BEGIN PRIVATE KEY-----")) {
        throw new Error("Invalid PKCS8 private key format.");
      }

      const importedKey = await importPrivateKeyPem(pem);

      setPrivateKey(importedKey);
      setKeyStatus(
        `Private key loaded successfully (${file.name}).`
      );
    } catch (err) {
      console.error("Private key import failed:", err);

      setPrivateKey(null);
      setKeyStatus("");

      setError(
        "Unable to import private key. Please select the correct PKCS8 PEM private key."
      );
    } finally {
      event.target.value = "";
    }
  };

  // ------------------------------------------
  // UPLOAD ARTIFACT
  // ------------------------------------------

  const handleUpload = async (event) => {
    event.preventDefault();

    if (!selectedProject || !selectedFile) {
      setError("Please select a project and a file.");
      return;
    }

    const formData = new FormData();

    formData.append("project", selectedProject);
    formData.append("file", selectedFile);
    formData.append("description", description);
    formData.append("name", selectedFile.name);

    try {
      setUploading(true);
      setError("");
      setMessage("");

      await api.post("/artifacts/upload/", formData);

      setMessage("Encrypted artifact uploaded successfully.");

      setSelectedFile(null);
      setDescription("");

      await loadArtifacts();
    } catch (err) {
      console.error("Artifact upload failed:", err);

      setError(
        err.response?.data?.error ||
        err.response?.data?.detail ||
        "Artifact upload failed."
      );
    } finally {
      setUploading(false);
    }
  };

  // ------------------------------------------
  // UPLOAD NEW VERSION AND DISTRIBUTE KEYS
  // ------------------------------------------

  const handleUploadVersion = async (event) => {
    event.preventDefault();
    let currentStep = "Validating version upload";

    if (!versionUploadArtifact || !versionFile) {
      setError("Please select a file for the new version.");
      return;
    }

    if (!privateKey) {
      setError("Load your RSA private key before uploading a version.");
      return;
    }

    try {
      setVersionUploading(true);
      setError("");
      setMessage("");

      // 1. Upload the new version.
      currentStep = "Uploading the new version to the server";
      const formData = new FormData();
      formData.append("file", versionFile);

      const uploadResponse = await api.post(
        `/artifacts/${versionUploadArtifact.id}/versions/`,
        formData
      );

      const version = uploadResponse.data.version;

      if (!version?.id || !uploadResponse.data.wrapped_key) {
        throw new Error(
          "The server did not return the new version's encryption key."
        );
      }

      // 2. Retrieve existing recipients.
      currentStep = "Loading existing artifact recipients";
      const recipientsResponse = await api.get(
        `/artifacts/${versionUploadArtifact.id}/recipients/`
      );

      const recipients = recipientsResponse.data.recipients || [];

      // 3. Unwrap the new AES key locally using the owner's private key.
      currentStep = "Unwrapping the version AES key with your private key";
      const aesKey = await unwrapAESKey(
        uploadResponse.data.wrapped_key,
        privateKey,
        true
      );

      // 4. Wrap the AES key for each existing recipient.
      currentStep = "Preparing recipient-specific encryption keys";
      const wrappedKeys = [];

      for (const recipient of recipients) {
        currentStep = `Wrapping the AES key for recipient ${recipient.username}`;
        if (!recipient.public_key) {
          throw new Error(
            `${recipient.username} has no registered public key.`
          );
        }

        const recipientPublicKey = await importPublicKeyPem(
          recipient.public_key
        );

        const recipientWrappedKey = await wrapAESKey(
          aesKey,
          recipientPublicKey
        );

        wrappedKeys.push({
          user_id: recipient.user_id,
          wrapped_key: recipientWrappedKey
        });
      }

      // 5. Store all recipient-specific keys.
      currentStep = "Saving recipient keys on the server";
      await api.post(
        `/artifacts/${versionUploadArtifact.id}/versions/${version.id}/recipient-keys/`,
        {
          wrapped_keys: wrappedKeys
        }
      );

      // 6. Refresh artifact list and version history.
      currentStep = "Refreshing artifact and version history";
      setMessage(
        `Version ${version.version_number} uploaded successfully. ` +
        `Encryption keys distributed to ${recipients.length} existing recipient(s).`
      );

      setVersionFile(null);
      setVersionUploadArtifact(null);

      await loadArtifacts();

      const historyResponse = await api.get(
        `/artifacts/${versionUploadArtifact.id}/versions/`
      );

      setVersionHistories((previous) => ({
        ...previous,
        [versionUploadArtifact.id]: historyResponse.data.versions || []
      }));

      setExpandedVersionArtifact(versionUploadArtifact.id);

    } catch (err) {
      console.error("Version workflow failed at:", currentStep);
      console.error("Detailed error:", err);

      const detail = err?.response
        ? await getApiError(err)
        : (err?.message || "An unexpected error occurred.");

      setError(
        `Failed at: ${currentStep}. ${detail} ` +
        "Do not upload the same file again yet; the version may already exist."
      );
    } finally {
      setVersionUploading(false);
    }
  };
  // ------------------------------------------
  // DOWNLOAD AND DECRYPT ARTIFACT
  // ------------------------------------------

  const handleDownload = async (artifact, versionNumber = null) => {
    try {
      setDownloadingId(artifact.id);
      setError("");
      setMessage("");

      const response = await api.get(
        `/artifacts/${artifact.id}/download/`,
        {
          params: versionNumber ? { version: versionNumber } : {},
          responseType: "arraybuffer",
        }
      );

      const headers = response.headers;

      const encrypted =
        headers["x-artifact-encrypted"] === "true";

      const originalFilename = decodeBase64Filename(
        headers["x-artifact-original-filename"]
      );

      const expectedHash = headers["x-artifact-sha256"];

      let fileData;

      if (encrypted) {
        if (!privateKey) {
          throw new Error(
            "Please load your RSA private key before downloading encrypted artifacts."
          );
        }

        const algorithm = headers["x-artifact-algorithm"];
        const keyAlgorithm =
          headers["x-artifact-key-algorithm"];

        const nonce = headers["x-artifact-nonce"];
        const wrappedKey = headers["x-artifact-wrapped-key"];

        if (
          algorithm !== "AES-256-GCM" ||
          keyAlgorithm !== "RSA-OAEP-SHA256"
        ) {
          throw new Error(
            "Unsupported encryption or key-wrapping algorithm."
          );
        }

        if (!nonce || !wrappedKey) {
          throw new Error(
            "Encryption metadata is missing from the download response."
          );
        }

        // Unwrap the AES key using the user's RSA private key.
        const aesKey = await unwrapAESKey(
          wrappedKey,
          privateKey
        );

        // Convert downloaded ciphertext into Base64.
        const ciphertextBase64 = arrayBufferToBase64(
          response.data
        );

        // Decrypt the original file using AES-256-GCM.
        fileData = await decryptArtifact(
          ciphertextBase64,
          nonce,
          aesKey
        );
      } else {
        // Legacy unencrypted artifact.
        fileData = response.data;
      }

      // Verify the original plaintext SHA-256.
      if (expectedHash) {
        const actualHash = await calculateSHA256(fileData);

        if (
          actualHash.toLowerCase() !== expectedHash.toLowerCase()
        ) {
          throw new Error(
            "Integrity verification failed. The downloaded file does not match its original SHA-256 hash."
          );
        }
      }

      // Download only after successful decryption and verification.
      saveFile(fileData, originalFilename);

      setMessage(
        encrypted
          ? `Artifact decrypted and SHA-256 verified successfully: ${originalFilename}`
          : `Artifact downloaded and SHA-256 verified: ${originalFilename}`
      );
    } catch (err) {
      console.error("Artifact download failed:", err);

      setError(await getApiError(err));
    } finally {
      setDownloadingId(null);
    }
  };

  // ------------------------------------------
  // SHARE ARTIFACT SECURELY
  // ------------------------------------------

  const handleShareArtifact = async (event) => {
    event.preventDefault();

    if (!sharingArtifact || !recipientUsername.trim()) {
      setError("Please enter a recipient username.");
      return;
    }

    if (!privateKey) {
      setError("Load your RSA private key before sharing.");
      return;
    }

    try {
      setSharing(true);
      setError("");
      setMessage("");

      // 1. Retrieve the recipient's registered public key.
      const recipientResponse = await api.get(
        "/accounts/public-key/",
        {
          params: {
            username: recipientUsername.trim(),
          },
        }
      );

      if (!recipientResponse.data.public_key) {
        throw new Error(
          "The recipient has not registered an RSA public key."
        );
      }

      const recipientPublicKey = await importPublicKeyPem(
        recipientResponse.data.public_key
      );

      // 2. Retrieve the owner's wrapped AES keys.
      const keysResponse = await api.get(
        `/artifacts/${sharingArtifact.id}/sharing-keys/`
      );

      const sharingKeys = keysResponse.data.sharing_keys;

      if (!sharingKeys?.length) {
        throw new Error(
          "No encrypted versions are available to share."
        );
      }

      // 3. Unwrap each AES key locally and rewrap it
      // using the recipient's public key.
      const wrappedKeys = [];

      for (const item of sharingKeys) {
        if (
          item.key_encryption_algorithm !== "RSA-OAEP-SHA256"
        ) {
          throw new Error(
            "Unsupported key-wrapping algorithm."
          );
        }
        console.log("Version upload key metadata:", {
        versionId: version.id,
        keyAlgorithm: uploadResponse.data.key_encryption_algorithm,
        recipientKeyId: uploadResponse.data.recipient_key_id,
        });
        const aesKey = await unwrapAESKey(
          item.wrapped_key,
          privateKey,
          true
        );

        const recipientWrappedKey = await wrapAESKey(
          aesKey,
          recipientPublicKey
        );

        wrappedKeys.push({
          version_id: item.version_id,
          wrapped_key: recipientWrappedKey,
        });
      }

      // 4. Grant access and store recipient-specific wrapped keys.
      const shareResponse = await api.post(
        `/artifacts/${sharingArtifact.id}/share/`,
        {
          username: recipientUsername.trim(),
          permission: sharePermission,
          wrapped_keys: wrappedKeys,
        }
      );

      setMessage(
        `Artifact shared successfully with ${recipientUsername.trim()}.`
      );

      setSharingArtifact(null);
      setRecipientUsername("");
      setSharePermission("view");

      console.log("Share response:", shareResponse.data);
    } catch (err) {
      console.error("Artifact sharing failed:", err);

      setError(await getApiError(err));
    } finally {
      setSharing(false);
    }
  };
  // ------------------------------------------
  // MANAGE ARTIFACT ACCESS
  // ------------------------------------------

  const handleManageAccess = async (artifact) => {
    if (accessArtifact?.id === artifact.id) {
      setAccessArtifact(null);
      setArtifactRecipients([]);
      return;
    }

    try {
      setLoadingRecipients(true);
      setError("");
      setMessage("");
      setAccessArtifact(artifact);

      const response = await api.get(
        `/artifacts/${artifact.id}/recipients/`
      );

      setArtifactRecipients(response.data.recipients || []);
    } catch (err) {
      console.error("Loading artifact access failed:", err);
      setError(await getApiError(err));
      setAccessArtifact(null);
    } finally {
      setLoadingRecipients(false);
    }
  };

  const handleRevokeAccess = async (user) => {
    if (!accessArtifact) return;

    const confirmed = window.confirm(
      `Revoke ${user.username}'s access to "${accessArtifact.name}"?`
    );

    if (!confirmed) return;

    try {
      setRevokingUserId(user.user_id);
      setError("");
      setMessage("");

      await api.delete(
        `/artifacts/${accessArtifact.id}/share/${user.user_id}/`
      );

      setArtifactRecipients((previous) =>
        previous.filter((recipient) => recipient.user_id !== user.user_id)
      );

      setMessage(`Access revoked for ${user.username}.`);
    } catch (err) {
      console.error("Revoking artifact access failed:", err);
      setError(await getApiError(err));
    } finally {
      setRevokingUserId(null);
    }
  };
  // ------------------------------------------
  // USER INTERFACE
  // ------------------------------------------

  return (
    <div className="space-y-8">

      {/* PAGE HEADER */}

      <div>
        <h1 className="text-3xl font-bold text-slate-900">
          Artifact Management
        </h1>

        <p className="text-slate-500 mt-2">
          Upload, organize and securely download your project artifacts.
        </p>
      </div>

      {/* ERROR MESSAGE */}

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 p-4 rounded-xl">
          {error}
        </div>
      )}

      {/* SUCCESS MESSAGE */}

      {message && (
        <div className="bg-green-50 border border-green-200 text-green-700 p-4 rounded-xl">
          {message}
        </div>
      )}

      {/* PRIVATE KEY SECTION */}

      <section className="bg-white border rounded-2xl p-6 space-y-4">

        <h2 className="text-xl font-semibold">
          Encryption Key
        </h2>

        <p className="text-sm text-slate-500">
          Generate an encryption key pair for this account, or load an
          existing RSA private key to decrypt downloaded artifacts and
          securely share them with teammates. Your private key stays in
          this browser and is never uploaded to the server.
        </p>

        <button
          type="button"
          onClick={handleGenerateAndRegisterKey}
          disabled={generatingKey}
          className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-3 rounded-xl disabled:opacity-50"
        >
          {generatingKey
            ? "Generating and registering..."
            : "Generate and Register Encryption Key"}
        </button>

        <input
          type="file"
          accept=".pem"
          onChange={handlePrivateKeyUpload}
          className="w-full border rounded-xl p-3"
        />

        {keyStatus && (
          <p className="text-sm text-green-700">
            {keyStatus}
          </p>
        )}

        {privateKey && (
          <p className="text-sm text-indigo-600">
            RSA private key is available in this browser session.
          </p>
        )}

      </section>

      {/* UPLOAD SECTION */}

      <form
        onSubmit={handleUpload}
        className="bg-white border rounded-2xl p-6 space-y-4"
      >

        <h2 className="text-xl font-semibold">
          Upload Artifact
        </h2>

        <select
          value={selectedProject}
          onChange={(e) => setSelectedProject(e.target.value)}
          className="w-full border rounded-xl p-3"
          required
        >
          <option value="">Select a project</option>

          {projects.map((project) => (
            <option key={project.id} value={project.id}>
              {project.name}
            </option>
          ))}
        </select>

        <input
          type="file"
          onChange={(e) =>
            setSelectedFile(e.target.files?.[0] || null)
          }
          className="w-full border rounded-xl p-3"
          required
        />

        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Artifact description (optional)"
          className="w-full border rounded-xl p-3"
          rows={3}
        />

        <button
          type="submit"
          disabled={uploading}
          className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-3 rounded-xl disabled:opacity-50"
        >
          {uploading ? "Uploading..." : "Upload Artifact"}
        </button>

      </form>

      {/* ARTIFACT LIST */}

      <section className="bg-white border rounded-2xl p-6">

        <h2 className="text-xl font-semibold mb-5">
          Your Artifacts
        </h2>

        {loading ? (
          <p className="text-slate-500">Loading artifacts...</p>
        ) : artifacts.length === 0 ? (
          <p className="text-slate-500">No artifacts uploaded yet.</p>
        ) : (
          <div className="space-y-4">
            {artifacts.map((artifact) => (
              <div
                key={artifact.id}
                className="border rounded-xl p-4 space-y-4"
              >
                <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
                  <div>
                    <h3 className="font-semibold text-slate-900">
                      {artifact.name}
                    </h3>
                    <p className="text-sm text-slate-500 mt-1">
                      {artifact.description || "No description"}
                    </p>
                    <p className="text-xs text-slate-400 mt-2">
                      Artifact ID: {artifact.id}
                    </p>
                    <p className="text-xs text-slate-400 mt-1">
                      Current version: {artifact.current_version}
                    </p>
                    {artifact.versions?.some((version) => version.is_encrypted) && (
                      <p className="text-xs text-green-700 mt-2">
                        AES-256-GCM encrypted
                      </p>
                    )}
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => handleDownload(artifact)}
                      disabled={downloadingId === artifact.id}
                      className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-3 rounded-xl disabled:opacity-50"
                    >
                      {downloadingId === artifact.id ? "Downloading..." : "Download"}
                    </button>

                    <button
                      type="button"
                      onClick={() => handleViewVersions(artifact)}
                      disabled={loadingVersions}
                      className="border border-indigo-300 text-indigo-700 hover:bg-indigo-50 px-5 py-3 rounded-xl disabled:opacity-50"
                    >
                      {loadingVersions && expandedVersionArtifact === artifact.id
                        ? "Loading..."
                        : expandedVersionArtifact === artifact.id
                          ? "Hide Versions"
                          : "Version History"}
                    </button>

                    <button
                      type="button"
                      onClick={() => {
                        setSharingArtifact(artifact);
                        setRecipientUsername("");
                        setSharePermission("view");
                        setError("");
                        setMessage("");
                      }}
                      className="bg-emerald-600 hover:bg-emerald-700 text-white px-5 py-3 rounded-xl"
                    >
                      Share
                    </button>
                    <button
                        type="button"
                        onClick={() => {
                            setVersionUploadArtifact(artifact);
                            setVersionFile(null);
                            setError("");
                            setMessage("");
                        }}
                        className="bg-violet-600 hover:bg-violet-700 text-white px-5 py-3 rounded-xl"
                        >
                        Upload New Version
                    </button>
                    <button
                    type="button"
                    onClick={() => handleManageAccess(artifact)}
                    disabled={loadingRecipients}
                    className="border border-emerald-300 text-emerald-700 hover:bg-emerald-50 px-5 py-3 rounded-xl disabled:opacity-50"
                    >
                    {loadingRecipients && accessArtifact?.id === artifact.id
                        ? "Loading..."
                        : accessArtifact?.id === artifact.id
                        ? "Hide Access"
                        : "Manage Access"}
                    </button>
                  </div>
                </div>
                {versionUploadArtifact?.id === artifact.id && (
                    <form
                        onSubmit={handleUploadVersion}
                        className="border-t pt-4 space-y-3"
                    >
                        <h4 className="font-semibold text-slate-800">
                        Upload New Version
                        </h4>

                        <p className="text-sm text-slate-500">
                        A new encrypted version will be created. Existing recipients
                        will receive keys for this version without changing their permissions.
                        </p>

                        <input
                        type="file"
                        onChange={(e) => setVersionFile(e.target.files?.[0] || null)}
                        className="w-full border rounded-xl p-3"
                        required
                        />

                        <div className="flex gap-2">
                        <button
                            type="submit"
                            disabled={versionUploading || !privateKey || !versionFile}
                            className="bg-violet-600 hover:bg-violet-700 text-white px-5 py-3 rounded-xl disabled:opacity-50"
                        >
                            {versionUploading ? "Uploading and distributing keys..." : "Upload Version"}
                        </button>

                        <button
                            type="button"
                            onClick={() => {
                            setVersionUploadArtifact(null);
                            setVersionFile(null);
                            }}
                            disabled={versionUploading}
                            className="border px-5 py-3 rounded-xl disabled:opacity-50"
                        >
                            Cancel
                        </button>
                        </div>
                    </form>
                    )}
                {accessArtifact?.id === artifact.id && (
                    <div className="border-t pt-4 space-y-3">
                        <h4 className="font-semibold text-slate-800">
                        Shared With
                        </h4>

                        {artifactRecipients.length === 0 ? (
                        <p className="text-sm text-slate-500">
                            This artifact has not been shared with anyone.
                        </p>
                        ) : (
                        artifactRecipients.map((recipient) => (
                            <div
                            key={recipient.user_id}
                            className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 bg-slate-50 rounded-lg p-3"
                            >
                            <div>
                                <p className="font-medium text-slate-800">
                                {recipient.username}
                                </p>
                                <p className="text-sm text-slate-500">
                                Permission: {recipient.permission}
                                </p>
                            </div>

                            <button
                                type="button"
                                onClick={() => handleRevokeAccess(recipient)}
                                disabled={revokingUserId === recipient.user_id}
                                className="border border-red-300 text-red-700 hover:bg-red-50 px-4 py-2 rounded-lg disabled:opacity-50"
                            >
                                {revokingUserId === recipient.user_id
                                ? "Revoking..."
                                : "Revoke Access"}
                            </button>
                            </div>
                        ))
                        )}
                    </div>
                    )}
                {expandedVersionArtifact === artifact.id && (
                  <div className="border-t pt-4 space-y-3">
                    <h4 className="font-semibold text-slate-800">
                      Version History
                    </h4>

                    {(versionHistories[artifact.id] || []).length === 0 ? (
                      <p className="text-sm text-slate-500">No versions found.</p>
                    ) : (
                      versionHistories[artifact.id].map((version) => (
                        <div
                          key={version.id}
                          className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 bg-slate-50 rounded-lg p-3"
                        >
                          <div className="min-w-0">
                            <p className="font-medium text-slate-800">
                              Version {version.version_number}
                              {version.version_number === artifact.current_version && (
                                <span className="ml-2 text-xs text-green-700">
                                  Current
                                </span>
                              )}
                            </p>
                            <p className="text-sm text-slate-500 break-words">
                              {version.original_filename}
                            </p>
                            <p className="text-xs text-slate-400 mt-1">
                              Size: {Number(version.file_size).toLocaleString()} bytes
                            </p>
                            <p className="text-xs text-slate-400 break-all">
                              SHA-256: {version.sha256_hash}
                            </p>
                            <p className="text-xs text-slate-400">
                              Uploaded: {version.created_at
                                ? new Date(version.created_at).toLocaleString()
                                : "Unknown"}
                            </p>
                            <p className="text-xs text-slate-500">
                              {version.is_encrypted
                                ? `${version.encryption_algorithm} encrypted`
                                : "Legacy unencrypted version"}
                            </p>
                          </div>

                          <button
                            type="button"
                            onClick={() => handleDownload(artifact, version.version_number)}
                            disabled={downloadingId === artifact.id}
                            className="shrink-0 border border-indigo-300 text-indigo-700 hover:bg-indigo-50 px-4 py-2 rounded-lg disabled:opacity-50"
                          >
                            {downloadingId === artifact.id
                              ? "Downloading..."
                              : `Download v${version.version_number}`}
                          </button>
                        </div>
                      ))
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      {/* SHARE ARTIFACT FORM */}

      {sharingArtifact && (
        <section className="bg-white border rounded-2xl p-6 space-y-4">

          <div>
            <h2 className="text-xl font-semibold">
              Share Artifact
            </h2>

            <p className="text-sm text-slate-500 mt-1">
              Sharing: {sharingArtifact.name}
            </p>
          </div>

          <form
            onSubmit={handleShareArtifact}
            className="space-y-4"
          >

            <div>
              <label className="block text-sm font-medium mb-2">
                Teammate Username
              </label>

              <input
                type="text"
                value={recipientUsername}
                onChange={(e) =>
                  setRecipientUsername(e.target.value)
                }
                placeholder="Enter teammate's username"
                className="w-full border rounded-xl p-3"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-2">
                Access Permission
              </label>

              <select
                value={sharePermission}
                onChange={(e) =>
                  setSharePermission(e.target.value)
                }
                className="w-full border rounded-xl p-3"
              >
                <option value="view">
                  View only
                </option>

                <option value="download">
                  View and download
                </option>
              </select>
            </div>

            {!privateKey && (
              <p className="text-sm text-amber-700">
                Load your RSA private key before sharing.
              </p>
            )}

            <div className="flex flex-wrap gap-3">

              <button
                type="submit"
                disabled={sharing || !privateKey}
                className="bg-emerald-600 hover:bg-emerald-700 text-white px-6 py-3 rounded-xl disabled:opacity-50"
              >
                {sharing ? "Sharing..." : "Share Artifact"}
              </button>

              <button
                type="button"
                disabled={sharing}
                onClick={() => {
                  setSharingArtifact(null);
                  setRecipientUsername("");
                  setError("");
                }}
                className="border border-slate-300 hover:bg-slate-50 px-6 py-3 rounded-xl disabled:opacity-50"
              >
                Cancel
              </button>

            </div>

          </form>

        </section>
      )}

    </div>
  );
}

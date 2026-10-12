export async function pickFile(accept: string): Promise<File | null> {
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = accept;
    input.addEventListener(
      "change",
      () => resolve(input.files?.item(0) ?? null),
      { once: true },
    );
    input.click();
  });
}

export async function uploadFile(
  path: string,
  file: File,
): Promise<{ message: string }> {
  const body = new FormData();
  body.append("file", file);
  const response = await fetch(path, { method: "POST", body });
  if (!response.ok) throw new Error(`Upload failed (${response.status})`);
  return (await response.json()) as { message: string };
}

export async function downloadFile(
  path: string,
  filename: string,
): Promise<void> {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`Download failed (${response.status})`);
  const url = URL.createObjectURL(await response.blob());
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export async function downloadFile(
  path: string,
  filename: string,
): Promise<void> {
  const response = await fetch(path);
  if (!response.ok) throw new Error("download_failed");
  const url = URL.createObjectURL(await response.blob());
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export async function clipRead(): Promise<string> {
  try {
    return await navigator.clipboard.readText();
  } catch {
    return "";
  }
}

export async function clipWrite(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    /* noop */
  }
}

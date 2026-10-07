export const copyToClipboard = async (text: string): Promise<boolean> => {
  // Try using the modern Clipboard API first
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (err) {
      console.warn('Failed to copy using Clipboard API:', err);
    }
  }

  // Fallback: Using a temporary input element
  try {
    // Create a temporary input element
    const input = document.createElement('input');
    input.style.position = 'fixed';
    input.style.opacity = '0';
    input.value = text;
    document.body.appendChild(input);

    // Select the text
    input.select();
    input.setSelectionRange(0, input.value.length);

    // Try to copy
    const successful = document.execCommand('copy');
    document.body.removeChild(input);

    if (successful) {
      return true;
    }
  } catch (err) {
    console.warn('Failed to copy using input element:', err);
  }

  // Last resort for Safari: Create a temporary textarea that's visible
  try {
    // Remove any existing temporary elements
    const existingElements = document.querySelectorAll('.temp-clipboard-element');
    existingElements.forEach(el => el.remove());

    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.top = '50%';
    textarea.style.left = '50%';
    textarea.style.transform = 'translate(-50%, -50%)';
    textarea.style.width = '80%';
    textarea.style.height = '100px';
    textarea.style.zIndex = '9999';
    textarea.style.backgroundColor = 'white';
    textarea.style.color = 'black';
    textarea.style.padding = '10px';
    textarea.style.border = '1px solid #ccc';
    textarea.style.borderRadius = '4px';
    textarea.style.fontSize = '14px';
    textarea.style.fontFamily = 'monospace';
    textarea.style.resize = 'none';
    textarea.className = 'temp-clipboard-element';
    
    // Add instructions
    const instructions = document.createElement('div');
    instructions.style.position = 'fixed';
    instructions.style.top = 'calc(50% - 120px)';
    instructions.style.left = '50%';
    instructions.style.transform = 'translate(-50%, -50%)';
    instructions.style.backgroundColor = 'white';
    instructions.style.padding = '10px';
    instructions.style.borderRadius = '4px';
    instructions.style.zIndex = '10000';
    instructions.style.textAlign = 'center';
    instructions.style.fontFamily = 'sans-serif';
    instructions.style.color = 'black';
    instructions.innerHTML = 'Please select and copy the text below (Cmd+C or right-click → Copy)';
    instructions.className = 'temp-clipboard-element';

    // Add close button
    const closeButton = document.createElement('button');
    closeButton.innerHTML = '×';
    closeButton.style.position = 'fixed';
    closeButton.style.top = 'calc(50% - 150px)';
    closeButton.style.right = 'calc(10% + 10px)';
    closeButton.style.transform = 'translate(-50%, -50%)';
    closeButton.style.backgroundColor = 'white';
    closeButton.style.border = 'none';
    closeButton.style.borderRadius = '50%';
    closeButton.style.width = '24px';
    closeButton.style.height = '24px';
    closeButton.style.fontSize = '20px';
    closeButton.style.lineHeight = '24px';
    closeButton.style.cursor = 'pointer';
    closeButton.style.zIndex = '10001';
    closeButton.className = 'temp-clipboard-element';
    
    const removeElements = () => {
      const elements = document.querySelectorAll('.temp-clipboard-element');
      elements.forEach(el => el.remove());
    };

    closeButton.onclick = removeElements;
    
    // Add click outside handler
    const overlay = document.createElement('div');
    overlay.style.position = 'fixed';
    overlay.style.top = '0';
    overlay.style.left = '0';
    overlay.style.width = '100%';
    overlay.style.height = '100%';
    overlay.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
    overlay.style.zIndex = '9998';
    overlay.className = 'temp-clipboard-element';
    overlay.onclick = removeElements;

    document.body.appendChild(overlay);
    document.body.appendChild(instructions);
    document.body.appendChild(textarea);
    document.body.appendChild(closeButton);

    // Focus and select the text
    textarea.focus();
    textarea.select();

    // Return true to indicate that we've provided a way to copy
    // The actual copying will be done manually by the user
    return true;
  } catch (err) {
    console.warn('Failed to create temporary textarea:', err);
    return false;
  }
}; 
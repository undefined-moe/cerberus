import fs from 'fs';

/**
 * Extracts JS and CSS asset paths from HTML content using regex
 * @param {string} htmlContent - The HTML content to parse
 * @returns {Object} - Object containing js and css file paths
 */
function extractAssets(htmlContent) {
  const assets = {
    js: null,
    css: null
  };

  // Regex to match script tags with type="module" and extract src attribute
  const jsRegex = /<script.*src="(.*)">/i;
  const jsMatch = htmlContent.match(jsRegex);
  if (jsMatch) {
    assets.js = jsMatch[1];
  }

  // Regex to match link tags with rel="stylesheet" and extract href attribute
  const cssRegex = /<link.*href="(.*)">/i;
  const cssMatch = htmlContent.match(cssRegex);
  if (cssMatch) {
    assets.css = cssMatch[1];
  }

  return assets;
}

/**
 * Processes an HTML file and extracts assets
 * @param {string} inputFilePath - Path to the input HTML file
 * @param {string} outputFilePath - Path to the output JSON file
 */
function collectAssets(inputFilePath, outputFilePath) {
  try {
    // Read the HTML file
    const htmlContent = fs.readFileSync(inputFilePath, 'utf8');

    // Extract assets
    const assets = extractAssets(htmlContent);

    // Write to JSON file
    fs.writeFileSync(outputFilePath, JSON.stringify(assets, null, 2));

    console.log(`Assets extracted successfully:`);
    console.log(`  JS: ${assets.js || 'Not found'}`);
    console.log(`  CSS: ${assets.css || 'Not found'}`);
    console.log(`Output written to: ${outputFilePath}`);

    return assets;
  } catch (error) {
    console.error('Error processing file:', error.message);
    throw error;
  }
}

const args = process.argv.slice(2);

if (args.length !== 2) {
  console.log('Usage: node collect_assets.js <input_html_file> <output_json_file>');
  console.log('Example: node collect_assets.js index.html assets.json');
  process.exit(1);
}

const [inputFile, outputFile] = args;
collectAssets(inputFile, outputFile);
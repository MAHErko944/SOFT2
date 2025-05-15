function analyzeText(input) {
    if (typeof input !== 'string') throw new Error('Input must be a string');
  
    const trimmed = input.trim();
    const isEmpty = trimmed.length === 0;
  
    return {
      length: trimmed.length,
      hasNumbers: /\d/.test(trimmed),
      isEmpty,
      words: trimmed ? trimmed.split(/\s+/) : []
    };
  }

 module.exports=analyzeText
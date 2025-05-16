const analyzeText = require('../public/analyzer');
const app = require("../index");

// Testing input validation
describe("Input validation tests", () => {
  // Test that non-string inputs throw error
  it("should throw error when input is not a string", () => {
    expect(() => analyzeText(123)).toThrow();
  });
  
  // Test null input
  it("should throw error when input is null", () => {
    expect(() => analyzeText(null)).toThrow();
  });
  
  // Test undefined input
  it("should throw error when input is undefined", () => {
    expect(() => analyzeText(undefined)).toThrow();
  });
});

// Testing number detection
describe("Number detection tests", () => {
  // Test text with numbers
  it("should return true when text contains numbers", () => {
    const result = analyzeText("hello 123");
    expect(result.hasNumbers).toBe(true);
  });
  
  // Test text without numbers
  it("should return false when text doesn't contain numbers", () => {
    const result = analyzeText("hello world");
    expect(result.hasNumbers).toBe(false);
  });
});

// Testing text length functionality
describe("Text length tests", () => {
  // Test string length
  it("should return correct length of string", () => {
    const result = analyzeText("hello");
    expect(result.length).toBe(5);
  });
  
  // Test length with spaces
  it("should count spaces in the length", () => {
    const result = analyzeText("hello world");
    expect(result.length).toBe(11);
  });
  
  // Test empty string
  it("should return zero length for empty string", () => {
    const result = analyzeText("");
    expect(result.length).toBe(0);
  });
});

// Testing word counting and array functionality
describe("Word array tests", () => {
  // Test word counting
  it("should return correct number of words", () => {
    const result = analyzeText("software engineering is a cs subject");
    expect(result.words.length).toBe(6);
  });
  
  // Test word inclusion
  it("should include specific words in the array", () => {
    const result = analyzeText("software engineering is a cs subject");
    expect(result.words).toContain("cs");
    expect(result.words).toContain("software");
  });
  
  // Test exact word array
  it("should return correct word array", () => {
    const result = analyzeText("Hello world 123");
    expect(result.words).toEqual(["Hello", "world", "123"]);
  });
  
  // Test empty string case
  it("should return empty array for empty string", () => {
    const result = analyzeText("");
    expect(result.words).toEqual([]);
  });
});

// Testing isEmpty property
describe("Empty string detection tests", () => {
  // Test empty string
  it("should return true when text is empty", () => {
    const result = analyzeText("");
    expect(result.isEmpty).toBe(true);
  });
  
  // Test non-empty string
  it("should return false when text is not empty", () => {
    const result = analyzeText("hello");
    expect(result.isEmpty).toBe(false);
  });
  
  // Test string with only spaces
  it("should handle strings with only spaces", () => {
    const result = analyzeText("   ");
    expect(result.isEmpty).toBe(true); // Updated expectation
  });
});

// Testing the entire object structure
describe("Complete object structure tests", () => {
  // Test full object structure
  it("should return correct object structure", () => {
    const result = analyzeText("hello 123");
    const expected = {
      length: 9,
      hasNumbers: true,
      isEmpty: false,
      words: ["hello", "123"]
    };
    expect(result).toEqual(expected);
  });
  
  // Test property existence
  it("should have all expected properties", () => {
    const result = analyzeText("test");
    expect(result).toHaveProperty("length");
    expect(result).toHaveProperty("hasNumbers");
    expect(result).toHaveProperty("isEmpty");
    expect(result).toHaveProperty("words");
  });
  
  // Test specific property value
  it("should have correct specific property values", () => {
    const result = analyzeText("hello 123");
    expect(result).toHaveProperty("length", 9);
    expect(result).toHaveProperty("hasNumbers", true);
  });
});
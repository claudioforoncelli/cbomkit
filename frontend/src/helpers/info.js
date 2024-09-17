import { getDetections, capitalizeFirstLetter } from "@/helpers.js";
import dict from "../../resources/crypto-dictionary.json";

// The following functions depend on `dict`.
// Using another source of knowledge but keeping the same function signature would allow to easily remove reliance on the custom dict.

// Returns the full name of some cryptography term.
// If the full name cannot be found, if `canReturnShortName`, it will return a formatted version of the short `termName`. Else, it will return an empty string.
export function getTermFullName(termName, type, canReturnShortName = true) {
  // Check if the term name is in the database
  if (
    Object.hasOwn(dict, type) &&
    Object.hasOwn(dict[type], termName)
  ) {
    return dict[type][termName].fullName;
  } else {
    if (canReturnShortName) {
      // Try to return something without the help of the database
      if (type === "name") {
        return termName.toUpperCase();
      } else {
        return capitalizeFirstLetter(termName);
      }
    } else {
      // If the term name is not in the database, return ''
      return "";
    }
  }
}

export function getTermDescription(assetName, type) {
  // Check if the term description is in the database
  if (
    Object.hasOwn(dict, type) &&
    Object.hasOwn(dict[type], assetName)
  ) {
    return dict[type][assetName].description;
  } else {
    // If the term description is not in the database, return ''
    return "";
  }
}

// For a CBOM property inside `component.cryptoProperties.algorithmProperties`, wheter this property is a string or an array,
// this method will count the number of occurences of each different value of the property.
// It returns an array [ListOfObjectsContainingOccurences, NumberOfDifferentValues].
export function countOccurrences(algorithmProperty) {
  let detections = getDetections();

  const propertyOccurrences = {};
  let count = 0;

  // Check if "detections" key exists and is an array
  if (detections && Array.isArray(detections)) {
    // Iterate over each component
    detections.forEach((component) => {
      // Check if each component has the required fields
      if (
        component &&
        component.cryptoProperties &&
        component.cryptoProperties.algorithmProperties &&
        component.cryptoProperties.algorithmProperties[algorithmProperty]
      ) {
        const propertyRaw =
          component.cryptoProperties.algorithmProperties[algorithmProperty];
        // propertyRaw is either directly a string, or is an array of strings. We handle both cases below
        var propertyArray;
        if (Array.isArray(propertyRaw)) {
          propertyArray = propertyRaw;
        } else {
          propertyArray = [propertyRaw];
        }
        propertyArray.forEach((property) => {
          // Update the count of different property value
          if (!propertyOccurrences[property]) {
            count += 1;
          }
          // Update occurrences count
          propertyOccurrences[property] =
            (propertyOccurrences[property] || 0) + 1;
        });
      }
    });
  } else {
    console.error('"detections" key does not exist or is not an array.');
  }

  // Convert occurrences to the required format
  const occurrencesList = Object.entries(propertyOccurrences).map(
    ([group, value]) => ({
      name: group,
      group: group,
      value: value,
    })
  );

  return [occurrencesList, count];
}

// Same function as `countOccurrences` but special-cased for assets names instead of an algorithm property
export function countNames() {
  let detections = getDetections();

  const nameOccurrences = {};
  let count = 0;

  // Check if "detections" key exists and is an array
  if (detections && Array.isArray(detections)) {
    // Iterate over each component
    detections.forEach((component) => {
      // Check if each component has the required fields
      if (component && component.name) {
        // Update the count of different property value
        if (!nameOccurrences[component.name]) {
          count += 1;
        }
        // Update occurrences count
        nameOccurrences[component.name] =
          (nameOccurrences[component.name] || 0) + 1;
      }
    });
  } else {
    console.error('"detections" key does not exist or is not an array.');
  }

  // Convert occurrences to the required format
  const occurrencesList = Object.entries(nameOccurrences).map(
    ([group, value]) => ({
      name: group,
      group: group,
      value: value,
    })
  );

  return [occurrencesList, count];
}

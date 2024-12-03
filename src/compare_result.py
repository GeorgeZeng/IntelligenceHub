def compare_dicts(dict1, dict2):
    comparison_result = []

    # Compare values for the same keys
    for key in dict1.keys() | dict2.keys():  # Set union of keys in both dicts
        val1 = dict1.get(key, 'N/A')  # Value from dict1, or 'N/A' if key is missing
        val2 = dict2.get(key, 'N/A')  # Value from dict2, or 'N/A' if key is missing

        # Check if values are the same or different
        is_diff = val1 != val2

        # Append result as a tuple (key, value from dict1, value from dict2, is_diff)
        comparison_result.append((key, val1, val2, is_diff))
    
    return comparison_result
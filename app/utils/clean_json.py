from datetime import datetime
from typing import Any, Dict, List, Union
from pydantic import BaseModel


def clean_json_data(data: Any) -> Union[Dict, List, Any]:
    """
    Recursively clean data to make it JSON serializable
    Converts datetime objects to ISO format strings and Pydantic models to dicts
    """
    # Handle Pydantic models
    if isinstance(data, BaseModel):
        data = data.model_dump()
    
    # Handle dictionaries
    if isinstance(data, dict):
        cleaned = {}
        for key, value in data.items():
            if isinstance(value, datetime):
                cleaned[key] = value.isoformat()
            elif isinstance(value, BaseModel):
                cleaned[key] = clean_json_data(value.model_dump())
            elif isinstance(value, (dict, list)):
                cleaned[key] = clean_json_data(value)
            else:
                cleaned[key] = value
        return cleaned
    
    # Handle lists
    elif isinstance(data, list):
        return [
            clean_json_data(item) if isinstance(item, (dict, list, BaseModel))
            else item.isoformat() if isinstance(item, datetime)
            else item
            for item in data
        ]
    
    # Handle datetime
    elif isinstance(data, datetime):
        return data.isoformat()
    
    # Return as-is
    return data
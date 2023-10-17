#include "Response.h"


/* unpacks response buffer to response struct */
void Response::unpackResponse(char* buffer)
{
	//adds header
	memcpy(_response.Header.buffer, buffer, sizeof(_response.Header));
	char* payload = new char[_response.Header.BaseResponse.payload_size];
	memset(payload, 0, _response.Header.BaseResponse.payload_size);
	payload[_response.Header.BaseResponse.payload_size] = '\0';
	memcpy(payload, buffer + sizeof(_response.Header), _response.Header.BaseResponse.payload_size);
		
	if (_response.Header.BaseResponse.payload_size > 0) {
		_response.payload = new char[_response.Header.BaseResponse.payload_size];
		memcpy(_response.payload, payload, _response.Header.BaseResponse.payload_size);

	}
	
}

/* Returns the payload size. */
uint32_t Response::responseSizeLeft() const
{
	return (RESPONSE_SIZE - sizeof(_response.Header));
}
std::string Response::getPayload() {
	std::string payloadStr(_response.payload);
	return payloadStr;
}

/* constructor */
Response::Response()
{
	memset(_response.Header.buffer, 0, sizeof(_response.Header.BaseResponse));
	_response.Header.BaseResponse.version = VERSION;
	_response.payload = nullptr;
}

/* distractor */
Response::~Response()
{
	delete[] _response.payload;
}

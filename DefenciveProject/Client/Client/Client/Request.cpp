#include "Request.h"


/* inputs request information to buffer */
std::string Request::packRequest()
{
	//adds header
	
	char* buffer = new char[REQUEST_SIZE];
	memcpy(buffer, _request.Header.buffer, sizeof(_request.Header));

	if (_request.payload != nullptr) {
		//adds payload size
		uint32_t payloadSize = _request.Header.BaseRequest.payload_size;
		//calculate current payload size
		uint32_t currPayload = payloadSize < requestSizeLeft() ? payloadSize : requestSizeLeft();
		//adds payload
		memcpy(buffer + sizeof(_request.Header), _request.payload, currPayload);
	}
	std::string packedRequest(buffer, REQUEST_SIZE);
	return packedRequest;

}
/* Returns the payload size. */
uint32_t Request::requestSizeLeft() const
{
	return (REQUEST_SIZE - sizeof(_request.Header));
}
const char* Request::getPayload() const {
	return _request.payload;
}
/* constructor */
Request::Request()
{
	memset(_request.Header.buffer, 0, sizeof(_request.Header.BaseRequest));
	_request.Header.BaseRequest.version = VERSION;
	_request.payload = nullptr;
}

/* distractor */
Request::~Request()
{
	delete[] _request.payload;
}

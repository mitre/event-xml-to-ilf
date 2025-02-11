
#include <windows.h>
#include <conio.h>
#include <winevt.h>
#include <codecvt>

#pragma comment(lib, "wevtapi.lib")
DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent);
DWORD PrintEvent(EVT_HANDLE hEvent);

void windows_stream_wrapper()
{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hSubscription = NULL;
    LPWSTR pwsPath = (LPWSTR)L"ForwardedEvents";
    LPWSTR pwsQuery = (LPWSTR)L"*";

    // Subscribe to events beginning with the oldest event in the channel. The subscription
    // will return all current events in the channel and any future events that are raised
    // while the application is active.
    hSubscription = EvtSubscribe(NULL, NULL, pwsPath, pwsQuery, NULL, NULL,
        (EVT_SUBSCRIBE_CALLBACK)SubscriptionCallback, EvtSubscribeStartAtOldestRecord);
    if (NULL == hSubscription)
    {
        status = GetLastError();

        if (ERROR_EVT_CHANNEL_NOT_FOUND == status)
            wprintf(L"Channel %s was not found.\n", pwsPath);
        else if (ERROR_EVT_INVALID_QUERY == status)
            // You can call EvtGetExtendedStatus to get information as to why the query is not valid.
            wprintf(L"The query \"%s\" is not valid.\n", pwsQuery);
        else
            wprintf(L"EvtSubscribe failed with %lu.\n", status);

        goto cleanup;
    }

    wprintf(L"Hit any key to quit\n\n");
    while (!_kbhit())
        Sleep(10);

cleanup:

    if (hSubscription)
        EvtClose(hSubscription);
}

// convert wstring to UTF-8 string
std::string wstring_to_utf8 (const std::wstring& str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.to_bytes(str);
}

// The callback that receives the events that match the query criteria. 
DWORD WINAPI SubscriptionCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID pContext, EVT_HANDLE hEvent)
{
    UNREFERENCED_PARAMETER(pContext);

    DWORD status = ERROR_SUCCESS;

    switch (action)
    {
        // You should only get the EvtSubscribeActionError action if your subscription flags 
        // includes EvtSubscribeStrict and the channel contains missing event records.
    case EvtSubscribeActionError:
        if (ERROR_EVT_QUERY_RESULT_STALE == (DWORD)hEvent)
        {
            wprintf(L"The subscription callback was notified that event records are missing.\n");
            // Handle if this is an issue for your application.
        }
        else
        {
            wprintf(L"The subscription callback received the following Win32 error: %lu\n", (DWORD)hEvent);
        }
        break;

    case EvtSubscribeActionDeliver:
        if (ERROR_SUCCESS != (status = PrintEvent(hEvent)))
        {
            goto cleanup;
        }
        break;

    default:
        wprintf(L"SubscriptionCallback: Unknown action.\n");
    }

cleanup:

    if (ERROR_SUCCESS != status)
    {
        // End subscription - Use some kind of IPC mechanism to signal
        // your application to close the subscription handle.
    }

    return status; // The service ignores the returned status.
}

// Render the event as an XML string and print it.
DWORD PrintEvent(EVT_HANDLE hEvent)
{
    DWORD status = ERROR_SUCCESS;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    LPWSTR pRenderedContent = NULL;
    std::wstring w;
    std::string s;

    if (!EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount))
    {
        if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError()))
        {
            dwBufferSize = dwBufferUsed;
            pRenderedContent = (LPWSTR)malloc(dwBufferSize);
            if (pRenderedContent)
            {
                EvtRender(NULL, hEvent, EvtRenderEventXml, dwBufferSize, pRenderedContent, &dwBufferUsed, &dwPropertyCount);
            }
            else
            {
                wprintf(L"malloc failed\n");
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if (ERROR_SUCCESS != (status = GetLastError()))
        {
            wprintf(L"EvtRender failed with %d\n", status);
            goto cleanup;
        }
    }
    
    w = wstring(pRenderedContent);
    s = wstring_to_utf8(w);
    translator->run_from_string(s);

 cleanup:
    if (pRenderedContent)
        free(pRenderedContent);

    return status;

}
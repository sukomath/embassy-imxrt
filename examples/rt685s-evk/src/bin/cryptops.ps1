param(
    [string]$dataToWrite,
    [char]$mode
)
# Set COM port parameters
$portName = "COM9" # Replace with your COM port
$baudRate = 115200
$parity = "None"
$dataBits = 8
$stopBits = "One"

# Create a SerialPort object
try {
    $serialPort = New-Object System.IO.Ports.SerialPort $portName,$baudRate,$parity,$dataBits,$stopBits
    $serialPort.ReadTimeout = 10000 # Set read timeout to 1 second
    $serialPort.WriteTimeout = 1000 # Set write timeout to 1 second
    $serialPort.Open()
    Write-Host "Port $($portName) opened successfully." -ForegroundColor Green

    if ($mode -eq 'd') {

        if ($dataToWrite.Length -ne 64) {
            Write-Host "Invalid length" $dataToWrite.Length
            exit 0
        }

    $byteArray = [byte[]]::new($dataToWrite.Length / 2)
    for ($i = 0; $i -lt $dataToWrite.Length; $i += 2) {
        $byteArray[$i / 2] = [Convert]::ToByte($dataToWrite.Substring($i, 2), 16)
    }

    $decData = [byte[]]::new($byteArray.Length + 1)

    [Array]::Copy($byteArray, 0, $decData, 1, $byteArray.Length)
    $decData[0] = 0x64;
    Write-Host "Sending hex byte array to decrypt: '$decData'"
    Write-Host $decData.Length
    $serialPort.Write($decData, 0, $decData.Length)

    }
    else {

        #if ($dataToWrite.Length -lt 32) {
        #}
        $byteArray = [byte[]]::new(32)
        <#
        for ($i = 0; $i -lt $dataToWrite.Length; $i += 1) {
            $byteArray[$i] = [Convert]::ToByte($dataToWrite.Substring($i, 1), 16)
        }#>

        $byteArray = [System.Text.Encoding]::ASCII.GetBytes($dataToWrite)

        $decData = [byte[]]::new(33)

        [Array]::Copy($byteArray, 0, $decData, 1, $byteArray.Length)
        $decData[0] = 0x65;
        Write-Host "Sending hex byte array to encrypt: '$decData'"
        Write-Host $decData.Length
        $serialPort.Write($decData, 0, $decData.Length)

        <#
        Write-Host "Writing plain text for encryption: '$dataToWrite'"
        $serialPort.WriteLine($dataToWrite)
        #>
   }
    # Read data from the COM port
    #$readBuff = [byte[]]::new(33)
    Write-Host "Reading data..."
    <#
    $receivedData = $serialPort.ReadLine();

    if ($mode -eq 'e') {
        $stringBytes = [System.Text.Encoding]::ASCII.GetBytes($receivedData)
        $hexString = ""
        foreach ($byte in $stringBytes) {
            $hexString += "{0:X2}" -f $byte
        }
        $receivedData = $hexString
    }
    Write-Host $receivedData
    #>

    $bytesToRead = 33
    if ($bytesToRead -gt 0) {
        $buffer = New-Object byte[] $bytesToRead
        $bytesRead = $serialPort.Read($buffer, 0, $bytesToRead)
        Start-Sleep -Seconds 1
        $bytesRead = $serialPort.Read($buffer, 1, $bytesToRead-1)
        $bytesRead += 1
        Write-Host "Read $bytesRead bytes:"
    }
    
    if ($mode -eq 'e') {
        $hexString = ""
        for ($i = 0; $i -lt $bytesRead; $i++) {
            $hexString += "{0:X2}" -f $buffer[$i]
        }
        Write-Host $hexString
    }
    else { 
        if ($mode -eq 'd') {
            $asciiString = [System.Text.Encoding]::ASCII.GetString($buffer)
            Write-Host  "Received data new: $asciiString" -ForegroundColor Cyan
        }
    }

}
catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    # Close the COM port
    if ($serialPort -ne $null -and $serialPort.IsOpen) {
        $serialPort.Close()
        Write-Host "Port $($portName) closed." -ForegroundColor Yellow
    }
}
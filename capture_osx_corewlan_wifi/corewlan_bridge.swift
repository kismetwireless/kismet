
var channels = [Int]()

@_silgen_name("swiftFunction")
public func swiftFunction(number: Int) -> Int
{
    print("swift called \(number)");
    return 42;
}

@_silgen_name("getChannels")
public func getChannels() -> Int 
{
    channels.append(1);
    channels.append(2);
    channels.append(3);
    channels.append(4);
    channels.append(5);
    return 1;
}

@_silgen_name("getChannelsLength")
public func getChannelsLength() -> Int
{
    return channels.count;
}

@_silgen_name("getChannelsItem")
public func getChannelsItem(pos: Int) -> Int
{
    return channels[pos];
}

@_silgen_name("getInterfaceName")
public func getInterfaceName() -> String
{
    return "test interface";
}


using System;
using System.Collections;
using System.Collections.Generic;

public static class Utils
{
  public static List<Object> addList(List<Object> l, params Object[] itemsToAdd)
  {
    foreach (var item in l)
    {
      l.Add(item);
    }
    return l;
  }
}

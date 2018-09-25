using System;
using System.Collections;

public static class Utils
{
  public static List<T> addList(List<T> l, params Object[] itemsToAdd)
  {
    foreach (item : l)
    {
      l.add(item);
    }
    return l;
  }
}

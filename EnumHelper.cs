using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel;

namespace windiskhelper
{
    /// <summary>
    /// Extension methods for or realted to enums
    /// </summary>
    public static class EnumHelper
    {
        /// <summary>
        /// Get a given attribute for a given enum value
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="enumVal"></param>
        /// <returns></returns>
        public static T GetAttributeOfType<T>(this Enum enumVal) where T : System.Attribute
        {
            var type = enumVal.GetType();
            var memInfo = type.GetMember(enumVal.ToString());
            var attributes = memInfo[0].GetCustomAttributes(typeof(T), false);
            return (attributes.Length > 0) ? (T)attributes[0] : null;
        }

        /// <summary>
        /// Get the value of the Description attribute for a given enum value
        /// </summary>
        /// <param name="enumValue">The enum value to return the description of</param>
        /// <returns></returns>
        public static string GetDescription(this Enum enumValue)
        {
            var attribute = enumValue.GetAttributeOfType<DescriptionAttribute>();

            return attribute == null ? enumValue.ToString() : attribute.Description;
        }

        /// <summary>
        /// Return the enum value that matches the given description
        /// </summary>
        /// <typeparam name="T">The enum to search</typeparam>
        /// <param name="description">The description to search for</param>
        /// <returns></returns>
        public static T GetEnumValueFromDescription<T>(this string description)
        {
            var type = typeof(T);
            if (!type.IsEnum)
                throw new InvalidOperationException();

            foreach (var field in type.GetFields())
            {
                var attribute = Attribute.GetCustomAttribute(field,
                    typeof(DescriptionAttribute)) as DescriptionAttribute;
                if (attribute != null)
                {
                    if (attribute.Description == description)
                        return (T)field.GetValue(null);
                }
                else
                {
                    if (field.Name == description)
                        return (T)field.GetValue(null);
                }
            }
            throw new ArgumentException("Not found.", "description");
        }
    }
}
